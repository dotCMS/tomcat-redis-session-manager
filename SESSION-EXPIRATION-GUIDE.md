# Session Expiration in Redis Session Manager: A Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Session Types](#session-types)
3. [The Dual Storage Architecture](#the-dual-storage-architecture)
4. [How Session Expiration Works](#how-session-expiration-works)
5. [The Problem We Faced](#the-problem-we-faced)
6. [Why We Override processExpires()](#why-we-override-processexpires)
7. [Why We Override isValid()](#why-we-override-isvalid)
8. [The Complete Solution](#the-complete-solution)
9. [Examples and Scenarios](#examples-and-scenarios)

---

## Introduction

This document explains how session expiration works in the Redis Session Manager, the problems we encountered with Tomcat's standard expiration logic, and the solutions we implemented.

**The Core Problem**: Tomcat's standard session expiration mechanism was incorrectly expiring sessions that were still active in Redis, causing users to lose their sessions unexpectedly in clustered environments.

**The Solution**: Override key methods (`processExpires()` and `isValid()`) to implement session-type-aware expiration logic that uses Redis as the source of truth for session activity.

---

## Session Types

The Redis Session Manager handles two types of sessions with different expiration strategies:

### 1. Undefined Sessions (Anonymous/Unauthenticated)

**Characteristics**:
- No `DOT_CLUSTER_SESSION_ATTR` attribute set
- Typically new visitors who haven't logged in
- Short-lived in Redis (15 seconds by default)
- Managed by Tomcat's expiration logic

**Redis Storage**:
- TTL: 15 seconds (configurable via `TOMCAT_REDIS_UNDEFINED_SESSION_TYPE_TIMEOUT`)
- Purpose: Cluster coordination during authentication
- After 15s, Redis auto-deletes the entry

**Expiration**:
- **Managed by**: Tomcat's `processExpires()` based on idle time
- **Max Inactive Interval**: Standard Tomcat timeout (e.g., 1800s)
- **Logic**: If idle time exceeds max inactive interval, Tomcat expires the session

**Why This Design**:
- Most anonymous sessions never authenticate
- No need to burden Redis with long-term storage
- Tomcat is efficient at managing local sessions
- 15s Redis window prevents cluster race conditions during login

### 2. Authenticated Sessions (Redis-Managed)

**Characteristics**:
- Has `DOT_CLUSTER_SESSION_ATTR` attribute set
- User has logged in
- Long-lived in Redis (1800 seconds by default)
- Managed by Redis TTL expiration

**Redis Storage**:
- TTL: 1800 seconds (configurable via `TOMCAT_REDIS_USER_SESSION_TIMEOUT`)
- Purpose: Cluster-consistent session management
- TTL refreshed on every access

**Expiration**:
- **Managed by**: Redis TTL auto-expiration
- **Max Inactive Interval**: Same as Redis TTL (1800s)
- **Logic**: When Redis TTL reaches 0, Redis auto-deletes the session

**Why This Design**:
- Authenticated users need cluster-wide session availability
- Redis TTL ensures consistent expiration across all nodes
- No node can have stale session data
- User experience is consistent regardless of which node they hit

---

## The Dual Storage Architecture

### Storage Strategy

**All sessions are stored in BOTH Redis and Tomcat**:

```
┌─────────────────────────────────────────────────────────┐
│                    NEW SESSION                          │
│                         ↓                               │
│         ┌───────────────────────────────┐              │
│         │    Stored in BOTH locations:   │              │
│         │                                 │              │
│         │  1. Redis (with TTL)           │              │
│         │  2. Tomcat (in-memory)         │              │
│         └───────────────────────────────┘              │
│                         ↓                               │
│            Expiration Strategy Depends On:             │
│                                                         │
│    ┌─────────────────┬─────────────────────┐          │
│    │  Undefined      │  Authenticated      │          │
│    │  (no attribute) │  (has attribute)    │          │
│    ├─────────────────┼─────────────────────┤          │
│    │ Redis: 15s TTL  │ Redis: 1800s TTL    │          │
│    │ Expires in:     │ Expires in:         │          │
│    │ Tomcat          │ Redis               │          │
│    └─────────────────┴─────────────────────┘          │
└─────────────────────────────────────────────────────────┘
```

### Why Dual Storage?

1. **Cluster Coordination**: New sessions need to be visible across all nodes immediately
2. **Flexible Expiration**: Different strategies for different session types

---

## How Session Expiration Works

### Standard Tomcat Expiration (Base Class Behavior)

Tomcat's `StandardManager` has a background thread that runs `processExpires()` periodically (typically every 6 seconds):

```java
// StandardManager.processExpires() logic (simplified)
public void processExpires() {
    Session[] sessions = findSessions();

    for (Session session : sessions) {
        if (session.isValid()) {
            // Session is still valid after idle time check
            // Keep it
        } else {
            // Session expired (isValid() returned false)
            // It was already expired by isValid() check
        }
    }
}
```

The key is in `isValid()`:

```java
// StandardSession.isValid() logic (simplified)
public boolean isValid() {
    if (!this.valid) {
        return false;  // Already marked invalid
    }

    // Check idle time
    if (maxInactiveInterval > 0) {
        long timeIdle = (System.currentTimeMillis() - this.lastAccessedTime) / 1000L;
        if (timeIdle >= maxInactiveInterval) {
            expire();  // Expire the session
            return false;
        }
    }

    return true;
}
```

**Key Point**: `isValid()` checks idle time and **automatically expires** the session if it's been idle too long.

---

## The Problem We Faced

### Problem 1: Stale lastAccessedTime After Save/Load Cycles

**Scenario**:
```
T=0:   Session created, lastAccessedTime = 0
T=5:   User accesses page on Node A
       Session saved to Redis
       lastAccessedTime = 0 (stored in serialized form)

T=10:  User accesses page on Node B
       Session loaded from Redis
       lastAccessedTime = 0 (restored from serialized data - STALE!)
       Session processed and saved to Redis
       lastAccessedTime still = 0

T=30:  processExpires() runs on Node B
       Calculates: timeIdle = 30 - 0 = 30 seconds

       If maxInactiveInterval = 20 seconds:
       30 >= 20 → Session expired prematurely! ✗

       But user was just active at T=10!
```

**Root Cause**: The `lastAccessedTime` field in the serialized session data doesn't reflect all the intermediate accesses that happened during save/load cycles.

### Problem 2: Redis-Managed Sessions Expired by Tomcat

**Scenario**:
```
Authenticated session in cluster:
  Node A: User actively using the application
          lastAccessedTime = recent

  Node B: No direct access, but has session in Tomcat
          lastAccessedTime = 30 minutes ago (stale)

  Node B's processExpires() runs:
    Checks: timeIdle = 30 minutes
    Compares: 30 minutes >= maxInactiveInterval (30 minutes)
    Result: Expires the session! ✗

  Meanwhile, Redis still has the session (user is active on Node A)

  Next request to Node B:
    findSession() returns null (expired)
    User loses session despite being active! ✗
```

**Root Cause**: Each cluster node tracks its own `lastAccessedTime`. Node-specific idle time checks cause inconsistent expiration across the cluster.

### Problem 3: Cluster Race Condition

**Scenario**:
```
T=0:   User visits application
       Node A creates session
       Saves to Redis with 15s TTL

T=0.5: Load balancer routes next request to Node B
       Node B: No session found locally
       Node B: Queries Redis → Session found! ✓
       Session continues seamlessly

WITHOUT the 15s Redis window:
T=0.5: Node B: Queries Redis → Not found (Node A hasn't saved yet)
       Node B: Creates NEW session → User loses original session ✗
```

**Root Cause**: Without temporary Redis storage, new sessions aren't immediately visible to other cluster nodes.

---

## Why We Override processExpires()

### The Standard processExpires() Problem

Tomcat's `StandardManager.processExpires()` calls `isValid()` on every session, which:
1. Checks the `valid` flag
2. **Checks idle time** using `lastAccessedTime`
3. Expires the session if idle too long

**This doesn't work for us because**:
- `lastAccessedTime` becomes stale after save/load cycles
- Redis-managed sessions shouldn't be expired by Tomcat's local idle time checks
- We need different logic for different session types

### Our Override Solution

```java
@Override
public void processExpires() {
    Session[] sessions = findSessions();
    long timeNow = System.currentTimeMillis();

    for (Session session : sessions) {
        RedisSession redisSession = (RedisSession) session;

        // CRITICAL: Check validity first to avoid IllegalStateException
        if (!redisSession.isValid()) {
            continue;  // Skip invalid sessions
        }

        if (redisSession.getAttribute(DOT_CLUSTER_SESSION_ATTR) == null
                && !this.isAnonTrafficEnabled) {
            // ============================================
            // Case 1: Undefined Session (Tomcat-managed)
            // ============================================
            if (!redisSession.isNew()) {
                // Get ACCURATE lastAccessedTime from Redis TTL
                long lastAccessedTime = redisSession.getLastAccessedTime();
                int maxInactiveInterval = redisSession.getMaxInactiveInterval();
                long timeIdle = (timeNow - lastAccessedTime) / 1000L;

                // Expire if truly idle
                if (maxInactiveInterval > 0 && timeIdle >= maxInactiveInterval) {
                    redisSession.expire();
                }
            }
        } else {
            // ================================================
            // Case 2: Authenticated Session (Redis-managed)
            // ================================================
            // Check if session still exists in Redis
            if (!existsInRedis(redisSession.getId())) {
                // Redis TTL expired → Expire in Tomcat too
                redisSession.expire();
            }
            // If exists in Redis → Keep alive (Redis manages expiration)
        }
    }
}
```

### Key Improvements

1. **Session-Type-Aware Logic**:
   - Undefined sessions: Use accurate idle time from Redis TTL
   - Authenticated sessions: Check Redis existence, don't use idle time

2. **Accurate lastAccessedTime**:
   - Calculated from Redis TTL (source of truth)
   - Formula: `lastAccessedTime = currentTime - (originalTTL - remainingTTL)`
   - Prevents stale timestamp issues

3. **Memory Leak Prevention**:
   - Detects sessions expired in Redis but still in Tomcat
   - Cleans them up to prevent memory growth

---

## Why We Override isValid()

### The Standard isValid() Problem

Tomcat's `StandardSession.isValid()`:
```java
public boolean isValid() {
    if (!this.valid) {
        return false;
    }

    // PROBLEM: Always checks idle time
    if (maxInactiveInterval > 0) {
        long timeIdle = (System.currentTimeMillis() - this.lastAccessedTime) / 1000L;
        if (timeIdle >= maxInactiveInterval) {
            expire();  // Expires Redis-managed sessions prematurely!
            return false;
        }
    }

    return true;
}
```

**This doesn't work for Redis-managed sessions because**:
- Each cluster node has different `lastAccessedTime`
- Node-specific idle time checks cause inconsistent expiration
- Redis-managed sessions should ONLY be expired by Redis TTL, not local checks

### Our Override Solution

```java
@Override
public boolean isValid() {
    // CRITICAL: Check valid flag FIRST (prevent IllegalStateException)
    if (!getValidFlag()) {
        return false;
    }

    if (this.manager instanceof RedisSessionManager) {
        RedisSessionManager redisManager = (RedisSessionManager) this.manager;

        // Check if this is a Redis-managed session
        boolean isRedisManagedSession =
                this.getAttribute(DOT_CLUSTER_SESSION_ATTR) != null
                || redisManager.isAnonTrafficEnabled();

        if (isRedisManagedSession) {
            // ================================================
            // Redis-Managed Session:
            // Only check valid flag, skip idle time checks
            // ================================================
            return true;  // Already checked valid flag above
        }
    }

    // ================================================
    // Tomcat-Managed Session (Undefined):
    // Delegate to base class (includes idle time check)
    // ================================================
    return super.isValid();
}
```

### Key Improvements

1. **Session-Type-Aware Validation**:
   - Redis-managed: Only check valid flag (no idle time check)
   - Tomcat-managed: Full validation including idle time

2. **Prevents Premature Expiration**:
   - Redis-managed sessions aren't expired by Tomcat's local logic
   - Expiration managed consistently by Redis TTL across all nodes

3. **Cluster Consistency**:
   - All nodes return same result for Redis-managed sessions
   - No node-specific expiration decisions

---

## The Complete Solution

### How lastAccessedTime is Calculated

Instead of using the stale stored value, we calculate from Redis TTL:

```java
@Override
public long getLastAccessedTime() {
    // Check validity first
    if (!getValidFlag()) {
        throw new IllegalStateException("Session already invalidated");
    }

    if (this.manager instanceof RedisSessionManager) {
        RedisSessionManager redisManager = (RedisSessionManager) this.manager;

        try {
            // Query Redis for remaining TTL
            long remainingTTL = redisManager.getRemainingTTL(this.getId());

            if (remainingTTL >= 0) {
                // Determine the original TTL that was set in Redis
                // IMPORTANT: For undefined sessions, Redis TTL != maxInactiveInterval!
                long originalTTL;
                if (this.getAttribute(DOT_CLUSTER_SESSION_ATTR) != null
                        || redisManager.isAnonTrafficEnabled()) {
                    // Authenticated: Redis TTL = maxInactiveInterval (1800s)
                    originalTTL = this.getMaxInactiveInterval();
                } else {
                    // Undefined: Redis TTL = undefinedSessionTypeTimeout (15s)
                    originalTTL = redisManager.getUndefinedSessionTypeTimeout();
                }

                // Calculate time since last access
                long timeSinceLastAccess = (originalTTL - remainingTTL) * 1000L;
                long currentTime = System.currentTimeMillis();
                long calculatedLastAccessedTime = currentTime - timeSinceLastAccess;

                // Get stored value
                long storedLastAccessedTime = super.getLastAccessedTime();

                // Return most recent (handles edge cases)
                return Math.max(calculatedLastAccessedTime, storedLastAccessedTime);
            }
        } catch (Exception e) {
            // Fall back to stored value if Redis unavailable
        }
    }

    return super.getLastAccessedTime();
}
```

**Why This Works**:
- Redis TTL is refreshed on every access (across all nodes)
- TTL difference tells us exactly how long since last access
- Always accurate, regardless of save/load cycles

**CRITICAL: originalTTL vs maxInactiveInterval**:
- For **undefined sessions**: Redis TTL (15s) ≠ maxInactiveInterval (1800s)
  - Must use `undefinedSessionTypeTimeout` (15s) as originalTTL
  - Using maxInactiveInterval would give completely wrong results!
- For **authenticated sessions**: Redis TTL (1800s) = maxInactiveInterval (1800s)
  - Can use either value (they're synchronized)
- The `getLastAccessedTime()` method checks session type to determine correct originalTTL

---

## Examples and Scenarios

### Example 1: Undefined Session (Tomcat-Managed)

```
Timeline:
---------
T=0:   User visits site
       Session created
       Saved to Redis: TTL = 15s
       Saved to Tomcat: maxInactiveInterval = 1800s

T=10:  Session accessed on Node A
       Saved to Redis: TTL = 15s (refreshed)
       storedLastAccessedTime = 0 (stale!)

T=20:  Session loaded on Node B
       storedLastAccessedTime = 0 (stale!)

T=25:  Redis TTL expires (15s elapsed since T=10)
       Redis: Session deleted automatically
       Tomcat: Session still exists

T=30:  processExpires() runs on Node B

       OLD LOGIC (BROKEN):
         Uses storedLastAccessedTime = 0
         timeIdle = 30 - 0 = 30 seconds
         If maxInactiveInterval = 20s:
           30 >= 20 → Expire! ✗ WRONG!

       NEW LOGIC (FIXED):
         Session not in Redis (TTL expired)
         No remainingTTL available
         Falls back to stored value = 0
         timeIdle = 30 - 0 = 30 seconds
         maxInactiveInterval = 1800s
         30 < 1800 → Keep! ✓ CORRECT!

         (Session will eventually expire at T=1800)
```

### Example 2: Authenticated Session (Redis-Managed)

```
Timeline:
---------
T=0:    User logs in
        Session gets DOT_CLUSTER_SESSION_ATTR
        Saved to Redis: TTL = 1800s
        Saved to Tomcat on Node A: lastAccessedTime = 0

T=300:  User actively using app on Node A
        Every request refreshes Redis TTL to 1800s
        Node A's lastAccessedTime = recent

T=600:  Load balancer routes request to Node B
        Node B loads session from Redis
        Node B's lastAccessedTime = 0 (stale!)

T=1800: No activity for 1200 seconds

T=1800: processExpires() runs on Node B

        OLD LOGIC (BROKEN):
          Calls isValid()
          StandardSession.isValid():
            timeIdle = 1800 - 0 = 1800 seconds
            maxInactiveInterval = 1800s
            1800 >= 1800 → Expire! ✗
          Session expired on Node B
          Meanwhile, Redis still has it (TTL refreshed by Node A)
          User on Node A: Session alive ✓
          User on Node B: Session gone ✗
          INCONSISTENT!

        NEW LOGIC (FIXED):
          Calls isValid()
          RedisSession.isValid():
            Has DOT_CLUSTER_SESSION_ATTR → Redis-managed
            Returns true (only checks valid flag)
          processExpires():
            Checks existsInRedis() → True (still in Redis)
            Keeps session alive ✓
          ALL NODES: Session alive ✓
          CONSISTENT!

T=3600: User stops activity
        No requests for 1800 seconds
        Redis TTL reaches 0
        Redis: Session deleted automatically

T=3606: processExpires() runs

        NEW LOGIC:
          Checks existsInRedis() → False
          Expires session in Tomcat ✓
          Session cleaned up properly ✓
```

### Example 3: Stale Timestamp with Redis TTL Calculation (Undefined Session)

```
Timeline:
---------
T=0:   Session created on Node A (undefined, not authenticated)
       Saved to Redis: TTL = 15s
       Tomcat: maxInactiveInterval = 1800s (Tomcat's default)
       storedLastAccessedTime = 0

T=5:   Request on Node A
       Saved to Redis: TTL = 15s (refreshed)
       storedLastAccessedTime = 0 (not updated in serialized form)

T=10:  Request on Node B
       Loaded from Redis
       storedLastAccessedTime = 0 (stale!)
       Saved back to Redis: TTL = 15s (refreshed)

T=15:  processExpires() runs on Node B

       Calculation with Redis TTL:
         Session type: Undefined (no DOT_CLUSTER_SESSION_ATTR)
         remainingTTL = 10s (15s TTL set at T=10, now T=15)

         IMPORTANT: originalTTL = undefinedSessionTypeTimeout (15s)
                    NOT maxInactiveInterval (1800s)!

         timeSinceLastAccess = 15 - 10 = 5 seconds
         calculatedLastAccessedTime = T=15 - 5s = T=10 ✓ ACCURATE!

         storedLastAccessedTime = T=0 (stale)

         Returns: max(T=10, T=0) = T=10 ✓

         timeIdle = T=15 - T=10 = 5 seconds
         maxInactiveInterval = 1800s (Tomcat's default)
         5 < 1800 → Keep! ✓ CORRECT!

NOTE: After T=25 (15s after T=10), Redis will auto-delete this session.
      Tomcat will continue managing it with maxInactiveInterval = 1800s.
      At that point, lastAccessedTime calculation will fall back to stored value.
```

---

## Summary

### The Problem
1. **Stale lastAccessedTime**: Became outdated after multiple save/load cycles
2. **Incorrect Expiration**: Tomcat expired sessions that were still active in Redis
3. **Cluster Inconsistency**: Different nodes made different expiration decisions

### The Solution
1. **Override processExpires()**: Implement session-type-aware expiration logic
2. **Override isValid()**: Skip idle time checks for Redis-managed sessions
3. **Override getLastAccessedTime()**: Calculate accurate time from Redis TTL

### The Result
- ✅ **Accurate Expiration**: Sessions expire based on real activity, not stale data
- ✅ **Cluster Consistency**: All nodes use Redis as source of truth
- ✅ **Correct Behavior**: Tomcat-managed sessions use local expiration, Redis-managed sessions use Redis TTL
- ✅ **No Premature Expiration**: Active sessions stay alive across the cluster

### Key Insights

1. **Redis TTL is the Source of Truth**: Always accurate, refreshed on every access
2. **Different Sessions, Different Rules**: Undefined vs authenticated sessions need different expiration strategies
3. **Dual Storage Benefits**: Combines Redis consistency with Tomcat performance
4. **Session Type Matters**: Must know whether session is Tomcat-managed or Redis-managed

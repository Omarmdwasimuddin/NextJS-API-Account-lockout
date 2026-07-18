## NextJS API: Account-lockout

![](https://imgur.com/49YXyNy.png)

### schema.prisma
```bash
model User {
  id                    String   @id @default(cuid())
  name                  String
  email                 String   @unique
  passwordHash          String
  role                  Role     @default(USER)
  isVerified            Boolean  @default(false)

  failedLoginAttempts   Int      @default(0)
  lockedUntil           DateTime?

  createdAt             DateTime @default(now())
  updatedAt             DateTime @updatedAt
  refreshTokens RefreshToken[]
  emailOtps     EmailOtp[]
}
```
---

### lib/auth/lockout.ts
```bash
import prisma from "@/lib/prisma";

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

// ---- lockedUntil future e ache kina check kore ----
export function isAccountLocked(lockedUntil: Date | null): boolean {
  if (!lockedUntil) return false;
  return lockedUntil > new Date();
}

// ---- wrong password er por call hobe: attempt count barabe,
// threshold pouche gele lock koray dibe ----
export async function recordFailedAttempt(userId: string, currentAttempts: number) {
  const newAttempts = currentAttempts + 1;
  const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;

  await prisma.user.update({
    where: { id: userId },
    data: {
      failedLoginAttempts: newAttempts,
      lockedUntil: shouldLock
        ? new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000)
        : undefined, // ---- undefined mane field touch e hobe na, ager value thakbe ----
    },
  });

  return { newAttempts, locked: shouldLock };
}

// ---- successful login er por call hobe: counter reset ----
export async function resetFailedAttempts(userId: string) {
  await prisma.user.update({
    where: { id: userId },
    data: {
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });
}

export { MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MINUTES };
```
---

###
```bash

```
---

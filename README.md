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

### app/api/auth/login/route.ts
```bash
import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { log } from "@/lib/logger"
import { handlePrismaError } from "@/lib/errors/handlePrismaError";
import { loginSchema } from "@/lib/validations/user.schema";
import { verifyPassword } from "@/lib/auth/password";
import { signAccessToken, generateRefreshToken } from "@/lib/auth/tokens";
import { ipRateLimit, emailRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/get-client-ip";
import { isAccountLocked, recordFailedAttempt, resetFailedAttempts } from "@/lib/auth/lockout";

export async function POST(request: NextRequest) {
    const requestId = crypto.randomUUID();
    try {
        log.info(
            {
                requestId,
                path: request.nextUrl.pathname,
                method: request.method,
            },
            "Login data received"
        )

        // ---- Step 1: IP rate limit check (body parse করার আগেই, কারণ এটা cheapest check) ----
        const clientIp = getClientIp(request);
        const ipResult = await ipRateLimit.limit(clientIp);

        if (!ipResult.success) {
            log.warn(
                {
                    requestId,
                    ip: clientIp,
                    remaining: ipResult.remaining,
                    reset: ipResult.reset,
                },
                "IP rate limit exceeded on login"
            )
            return NextResponse.json(
                {
                    status: "fail",
                    requestId,
                    message: "Too many login attempts. Please try again later.",
                },
                {
                    status: 429,
                    headers: {
                        "Retry-After": Math.ceil((ipResult.reset - Date.now()) / 1000).toString(),
                    },
                }
            )
        }

        const jsonBody = await request.json();
        const validation = loginSchema.safeParse(jsonBody);

        if (!validation.success) {
            log.warn(
                {
                    requestId,
                    errors: validation.error.flatten().fieldErrors,
                },
                "Invalid Input"
            )
            return NextResponse.json(
                {status: "fail", requestId, message: "Invalid Input", errors: validation.error.flatten().fieldErrors},
                {status: 400}
            )
        }

        const { email, password } = validation.data;

        // ---- Step 2: Email rate limit check (body validate হওয়ার পর, কারণ email লাগবে) ----
        const emailResult = await emailRateLimit.limit(email);

        if (!emailResult.success) {
            log.warn(
                {
                    requestId,
                    email,
                    ip: clientIp,
                    reset: emailResult.reset,
                },
                "Email rate limit exceeded on login"
            )
            return NextResponse.json(
                {
                    status: "fail",
                    requestId,
                    message: "Too many attempts for this account. Please try again later.",
                },
                {
                    status: 429,
                    headers: {
                        "Retry-After": Math.ceil((emailResult.reset - Date.now()) / 1000).toString(),
                    },
                }
            )
        }

        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            log.warn({ requestId, email }, "Failed login attempt - user not found");
            return NextResponse.json(
                {status: "fail", requestId, message: "Invalid email or password"},
                {status: 401}
            )
        }

        // ---- Account lock check — password verify korar age ----
        if (isAccountLocked(user.lockedUntil)) {
            const retryAfterSeconds = Math.ceil((user.lockedUntil!.getTime() - Date.now()) / 1000);

            log.warn(
                { requestId, userId: user.id, email, lockedUntil: user.lockedUntil },
                "Login attempt on locked account"
            )

            return NextResponse.json(
                {
                    status: "fail",
                    requestId,
                    message: "Account temporarily locked due to too many failed attempts. Please try again later.",
                    code: "ACCOUNT_LOCKED",
                },
                { status: 423, headers: { "Retry-After": retryAfterSeconds.toString() } }
            )
        }

        const passwordValid = await verifyPassword(user.passwordHash, password);

        if (!passwordValid) {
            const { newAttempts, locked } = await recordFailedAttempt(user.id, user.failedLoginAttempts);

            log.warn(
                { requestId, userId: user.id, email, attempts: newAttempts, locked },
                locked ? "Account locked after max failed attempts" : "Failed login attempt"
            )

            return NextResponse.json(
                {status: "fail", requestId, message: "Invalid email or password"},
                {status: 401}
            )
        }

        if (user.failedLoginAttempts > 0) {
            await resetFailedAttempts(user.id);
        }

        if (!user.isVerified) {
            log.warn(
                {
                    requestId,
                    userId: user.id,
                    email,
                },
                "Login attempt with unverified email"
            )

            return NextResponse.json(
                {status: "fail", requestId, message: "Please verify your email before logging in", code: "EMAIL_NOT_VERIFIED"},
                {status: 403}
            )
        }

        const accessToken = await signAccessToken(user.id, user.role);
        const { raw: refreshRaw, hashed: refreshHashed } = generateRefreshToken();

        await prisma.refreshToken.create({
            data: {
                tokenHash: refreshHashed,
                userId: user.id,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            },
        });

        const response = NextResponse.json({
            status: "success",
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
            },
        });

       response.cookies.set("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 15,
       }) 

       response.cookies.set("refresh_token", refreshRaw, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/api/auth",
        maxAge: 60 * 60 * 24 * 7,
       })

       log.info(
            {
                requestId,
                userId: user.id,
                email: user.email,
            },
            "User logged in"
        )
        
        return response;
        
    } catch (error) {
        const { status, message } = handlePrismaError(error);
        log.error(
        { 
            requestId,
            err: error instanceof Error 
                ? { message: error.message, stack: error.stack, name: error.name }
                : String(error),
        },
        message
    )
    return NextResponse.json(
        { status: "fail", requestId, message },
        { status }
    )
    }
}
```
---

-- TC-1483: per-sign-in app record for scoreboard counts. (userId, origin, UTC day) only.
CREATE TABLE "app_sign_in_day" (
    "userId" TEXT NOT NULL,
    "origin" TEXT NOT NULL,
    "day" DATE NOT NULL,
    CONSTRAINT "app_sign_in_day_pkey" PRIMARY KEY ("userId", "origin", "day")
);

CREATE INDEX "app_sign_in_day_day_idx" ON "app_sign_in_day"("day");
ALTER TABLE "app_sign_in_day" ADD CONSTRAINT "app_sign_in_day_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

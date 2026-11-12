-- Screenshot of the listed page: object key in the R2 bucket served at IMG_BASE.
ALTER TABLE sites ADD COLUMN shot TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN shot_at INTEGER NOT NULL DEFAULT 0;

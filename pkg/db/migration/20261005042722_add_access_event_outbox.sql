-- Create "access_event_outbox" table
CREATE TABLE `access_event_outbox` (
  `event_id` text NOT NULL,
  `payload` blob NOT NULL,
  `created_at` datetime NOT NULL,
  `attempts` integer NOT NULL DEFAULT 0,
  `next_attempt_at` datetime NOT NULL,
  PRIMARY KEY (`event_id`)
);
-- Create index "accesseventoutbox_created_at" to table: "access_event_outbox"
CREATE INDEX `accesseventoutbox_created_at` ON `access_event_outbox` (`created_at`);
-- Create index "accesseventoutbox_next_attempt_at" to table: "access_event_outbox"
CREATE INDEX `accesseventoutbox_next_attempt_at` ON `access_event_outbox` (`next_attempt_at`);

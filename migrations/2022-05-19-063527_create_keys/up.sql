-- Your SQL goes here
CREATE TABLE keys (
  id            SERIAL PRIMARY KEY,
  idx           INTEGER NOT NULL,
  t             INTEGER NOT NULL,
  n             INTEGER NOT NULL,
  pub_key       VARCHAR NOT NULL,
  body 		      TEXT NOT NULL,
  published			BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX keys_pub_key ON keys (pub_key, idx);
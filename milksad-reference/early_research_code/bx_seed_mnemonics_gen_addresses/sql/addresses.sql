CREATE TABLE IF NOT EXISTS addresses(
  id SERIAL PRIMARY KEY,
  ts DECIMAL,
  address_path VARCHAR(100),
  address_type VARCHAR(20),
  coin VARCHAR(100),
  address VARCHAR(200),
  CONSTRAINT unique_coin_address UNIQUE (ts,coin,address),
  CONSTRAINT fk_ts FOREIGN KEY(ts) REFERENCES mnemonics(ts)
);

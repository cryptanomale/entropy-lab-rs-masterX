CREATE TABLE IF NOT EXISTS mnemonics(
  id SERIAL,
  ts decimal UNIQUE PRIMARY KEY,
  mnemonic TEXT
);

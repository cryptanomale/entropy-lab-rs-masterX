import psycopg2
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import execute_values
from bip_utils import Bip39SeedGenerator
from bip_utils import Bip44
from bip_utils import Bip44Changes
from bip_utils import Bip44Coins



def gen_addresses(
    ts: str,
    mnemonic: str,
    coin: Bip44Coins = Bip44Coins.BITCOIN
) -> list[tuple[str, str, str, str, str]]:
  return gen_bip44_addresses(ts, mnemonic, coin=coin)


def gen_bip44_addresses(
    ts: str,
    mnemonic: str,
    coin: Bip44Coins = Bip44Coins.BITCOIN,
    account_number: int = 0
) -> list[tuple[str, str, str, str, str]]:
  ADDR_NUM: int = 100
  account_type: str = "bip44"
  seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
  bip44_mst_ctx = Bip44.FromSeed(seed_bytes, coin)
# Derive BIP44 account keys: m/44'/0'/0'
  bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(account_number)
  coin_name = bip44_acc_ctx.m_coin_conf.CoinNames().Name()
# Derive BIP44 chain keys: m/44'/0'/0'/0
  bip39_account_path = f"m/44'/0'/0'/{account_number}"
  bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
  addresses: list[tuple[str, str, str, str, str]] = []

  for i in range(ADDR_NUM):
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(i)
    address = bip44_addr_ctx.PublicKey().ToAddress()
    bip39_address_path = f"{bip39_account_path}/{i}"
    address_tpl = (
      "{0:0.9f}".format(ts),
      coin_name,
      account_type,
      bip39_address_path,
      address
    )
    addresses.append(address_tpl)
  return addresses


def batch_insert_addresses(cursor, accounts: list[tuple[str, str, str, str, str]]):
  stmt = """INSERT INTO addresses
      (ts, coin, address_type, address_path, address)
    VALUES
      %s
    ON CONFLICT ON CONSTRAINT unique_coin_address DO NOTHING;
  """
  print(f"Inserting {len(accounts)} rows")
  execute_values(cursor, stmt, accounts)


def main(pool):
  mnemonics_query = "SELECT * FROM mnemonics"
  if(pool):
    print("Connection pool created")
  stream_conn = pool.getconn()

  stream_cursor = stream_conn.cursor("mnemonics_stream")
  stream_cursor.execute(mnemonics_query)

  for row in stream_cursor:
    ts = row[1]
    mnemonic = row[2]
    print(f"Generating addresses for: {ts}")
    addresses = gen_bip44_addresses(ts, mnemonic)
    print(f"Inserting addresses for: {ts}")
    ps_conn = pool.getconn()
    ps_cursor = ps_conn.cursor()
    batch_insert_addresses(ps_cursor, addresses)
    ps_cursor.close()
    ps_conn.commit()
    pool.putconn(ps_conn)
  print("Interated all mnemonics, shutting down...")
  stream_cursor.close()
  pool.putconn(stream_conn)

postgresql_pool = None

try:
  postgresql_pool = SimpleConnectionPool(1,5)
  main(postgresql_pool)
except (Exception, psycopg2.DatabaseError) as error:
  print("Error", error)
finally:
  if postgresql_pool:
    postgresql_pool.closeall
  print("PostgreSQL connection pool is closed")

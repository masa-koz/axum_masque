use tokio_rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};

#[derive(Debug, Clone)]
pub struct Store {
    conn: Connection,
}

impl Store {
    pub async fn new(path: &str) -> SqlResult<Self> {
        let conn = Connection::open(path).await?;
        conn.call(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS public_addresses (
                    sub TEXT PRIMARY KEY NOT NULL,
                    addr TEXT NOT NULL
                )",
                params![],
            )
        })
        .await?;
        Ok(Self { conn })
    }

    pub async fn insert(&self, sub: &str, addr: &str) -> SqlResult<()> {
        let conn = self.conn.clone();
        let sub = sub.to_string();
        let addr = addr.to_string();
        conn.call(move |conn| {
            conn.execute(
                "INSERT INTO public_addresses (sub, addr) VALUES (?1, ?2)",
                params![sub, addr],
            )
        })
        .await?;
        Ok(())
    }

    pub async fn get(&self, sub: &str) -> SqlResult<Option<String>> {
        let conn = self.conn.clone();
        let sub = sub.to_string();
        Ok(conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT addr FROM public_addresses WHERE sub = ?1")?;
                stmt.query_row(params![sub], |row| {
                    Ok(row.get::<_, String>(0)?)
                })
                .optional()
            })
            .await?)
    }
}

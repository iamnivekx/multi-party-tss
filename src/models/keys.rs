use diesel::pg::PgConnection;
use diesel::{prelude::*, debug_query};
use diesel::{delete, insert_into};
use rocket::serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::schema::keys;

#[derive(Insertable)]
#[table_name = "keys"]
pub struct NewKey<'a> {
    pub pub_key: &'a str,
    pub body: &'a str,
    pub idx: i32,
    pub t: i32,
    pub n: i32,
    pub created_at: SystemTime,
}

#[derive(Queryable, Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
// #[table_name = "keys"]
pub struct Key {
    pub id: i32,
    pub idx: i32,
    pub t: i32,
    pub n: i32,
    pub pub_key: String,
    pub body: String,
    pub verified: bool,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl Key {
    pub fn create_key(
        conn: &PgConnection,
        idx: i32,
        t: i32,
        n: i32,
        pub_key: &str,
        body: &str,
    ) -> QueryResult<usize> {
        let now = SystemTime::now();
        let new_key = NewKey {
            pub_key,
            body,
            idx,
            t,
            n,
            created_at: now,
        };
        insert_into(keys::table)
            .values(new_key)
            .on_conflict((keys::pub_key, keys::idx))
            .do_nothing()
            .execute(conn)
    }

    pub fn find_by_id(conn: &PgConnection, id: i32) -> QueryResult<Vec<Key>> {
        keys::table
            .filter(keys::id.eq(id))
            .order(keys::id)
            .limit(1)
            .load::<Key>(conn)
    }

    pub fn find_by_pub_key(
        conn: &PgConnection,
        pub_key: String,
        idx: Option<i32>,
    ) -> QueryResult<Key> {
        let mut query = keys::table.into_boxed();
        query = query.filter(keys::pub_key.eq(pub_key));

        if let Some(idx) = idx {
            query = query.filter(keys::idx.eq(idx));
        }
        info!("sql {}", debug_query::<diesel::pg::Pg, _>(&query).to_string());
        query.order(keys::id).first::<Key>(conn)
    }

    pub fn delete_by_id(conn: &PgConnection, id: i32) -> QueryResult<usize> {
        delete(keys::table.filter(keys::id.eq(id))).execute(conn)
    }
}

#[cfg(test)]
pub mod test {
    use super::Key;
    use crate::lib::establish_connection;

    #[tokio::test]
    async fn test_create_key() -> Result<(), anyhow::Error> {
        let connection = establish_connection()?;
        let idx = 1;
        let t = 1;
        let n = 2;
        let pub_key = "pub_key";
        let body = "body";

        let posted = Key::create_key(&connection, idx, t, n, pub_key, &body);
        println!("\nSaved draft  key {:?} ", posted);
        Ok(())
    }

    #[tokio::test]
    async fn test_find_key_by_id() -> Result<(), anyhow::Error> {
        let connection = establish_connection()?;
        let id = 1;

        let key = Key::find_by_id(&connection, id);
        println!("find draft {:?} ", key);
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_key_by_id() -> Result<(), anyhow::Error> {
        let connection = establish_connection()?;
        let id = 1;

        let key = Key::delete_by_id(&connection, id);
        println!("delete draft {:?} ", key);
        Ok(())
    }
}

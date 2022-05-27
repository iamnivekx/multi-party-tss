table! {
    keys (id) {
        id -> Int4,
        idx -> Int4,
        t -> Int4,
        n -> Int4,
        pub_key -> Varchar,
        body -> Text,
        published -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

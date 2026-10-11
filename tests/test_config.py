def test_db_url_keeps_special_characters_in_password(load_shared):
    shared = load_shared(db_password="p@ss/w:rd#1")

    assert shared.DB_URL.password == "p@ss/w:rd#1"
    assert shared.DB_URL.host == "db.example"
    assert shared.DB_URL.port == 5432
    assert shared.DB_URL.database == "unused"

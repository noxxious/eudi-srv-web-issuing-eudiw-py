test_cases = {
    "1": {
        "mDL": {
            "family_name": "Pavarde",
            "given_name": "Vardas",
            "birth_date": "2008-07-10",
            "document_number": "002447688",
            "portrait": "M",
            "driving_privileges": [
                {"vehicle_category_code": "AM", "issue_date": "2023-10-19"}
            ],
        }
    },
    "2": {
        "mDL": {
            "family_name": "Simpsoniene",
            "given_name": "Marge",
            "birth_date": "1966-03-18",
            "document_number": "00111111",
            "portrait": "F",
            "driving_privileges": [
                {"vehicle_category_code": "B1", "issue_date": "1990-04-20"},
                {"vehicle_category_code": "B", "issue_date": "1990-04-20"},
                {"vehicle_category_code": "AM", "issue_date": "1990-04-20"},
            ],
        }
    },
    "3": {
        "mDL": {
            "family_name": "Simpsonaite",
            "given_name": "Lisa",
            "birth_date": "1966-03-18",
            "document_number": "00222222",
            "portrait": "F",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B1",
                    "issue_date": "1990-04-20",
                    "codes": [{"code": "1.06"}],
                },
                {
                    "vehicle_category_code": "B",
                    "issue_date": "1990-04-20",
                    "codes": [{"code": "1.06"}],
                },
                {
                    "vehicle_category_code": "AM",
                    "issue_date": "1990-04-20",
                    "codes": [{"code": "1.06"}],
                },
            ],
        }
    },
    "4": {
        "mDL": {
            "family_name": "Homeris",
            "given_name": "Simpson",
            "birth_date": "1954-05-19",
            "document_number": "00333333",
            "portrait": "M",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B1",
                    "issue_date": "1990-04-20",
                    "codes": [
                        {"code": "1.01"},
                        {"code": "02"},
                        {"code": "64", "sign": "=", "value": "100"},
                    ],
                },
                {
                    "vehicle_category_code": "B",
                    "issue_date": "1990-04-20",
                    "codes": [
                        {"code": "1.01"},
                        {"code": "02"},
                        {"code": "64", "sign": "=", "value": "100"},
                    ],
                },
                {
                    "vehicle_category_code": "AM",
                    "issue_date": "1990-04-20",
                    "codes": [
                        {"code": "1.01"},
                        {"code": "02"},
                        {"code": "64", "sign": "=", "value": "100"},
                    ],
                },
            ],
        }
    },
    "5": {
        "mDL": {
            "family_name": "Sunus Simpsonas",
            "given_name": "Bartas",
            "birth_date": "1960-01-06",
            "document_number": "00444444",
            "portrait": "M",
            "driving_privileges": [
                {
                    "vehicle_category_code": "A",
                    "issue_date": "1992-02-11",
                    "codes": [{"code": "79.03"}],
                },
                {"vehicle_category_code": "B1", "issue_date": "1992-02-11"},
                {"vehicle_category_code": "B", "issue_date": "1992-02-11"},
                {"vehicle_category_code": "AM", "issue_date": "1992-02-11"},
            ],
        }
    },
    "6": {
        "mDL": {
            "family_name": "SHACHAR",
            "given_name": "MATTHEW MICHAEL CHARLES",
            "birth_date": "1960-01-06",
            "document_number": "00555555",
            "portrait": "M",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B1",
                    "issue_date": "2020-11-07",
                    "codes": [{"code": "78"}],
                },
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2020-11-07",
                    "codes": [{"code": "78"}],
                },
                {"vehicle_category_code": "AM", "issue_date": "2020-11-07"},
            ],
        }
    },
    "7": {
        "mDL": {
            "family_name": "KORS",
            "given_name": "MICHAEL",
            "birth_date": "1968-02-01",
            "document_number": "00666666",
            "portrait": "M",
            "driving_privileges": [
                {"vehicle_category_code": "A1", "issue_date": "1990-07-03"},
                {"vehicle_category_code": "A2", "issue_date": "1990-07-03"},
                {"vehicle_category_code": "A", "issue_date": "1990-07-03"},
                {"vehicle_category_code": "B1", "issue_date": "1987-01-09"},
                {"vehicle_category_code": "B", "issue_date": "1987-01-09"},
                {
                    "vehicle_category_code": "C1",
                    "issue_date": "1987-01-09",
                    "expiry_date": "2027-11-27",
                    "codes": [{"code": "95"}],
                },
                {
                    "vehicle_category_code": "C",
                    "issue_date": "1987-01-09",
                    "expiry_date": "2027-11-27",
                    "codes": [{"code": "95"}],
                },
                {
                    "vehicle_category_code": "D1",
                    "issue_date": "1990-07-03",
                    "expiry_date": "2024-11-27",
                },
                {
                    "vehicle_category_code": "D",
                    "issue_date": "1990-07-03",
                    "expiry_date": "2024-11-27",
                },
                {"vehicle_category_code": "BE", "issue_date": "1990-07-03"},
                {
                    "vehicle_category_code": "C1E",
                    "issue_date": "1990-07-03",
                    "expiry_date": "2027-11-27",
                    "codes": [{"code": "95"}],
                },
                {
                    "vehicle_category_code": "CE",
                    "issue_date": "1990-07-03",
                    "expiry_date": "2027-11-27",
                    "codes": [{"code": "95"}],
                },
                {
                    "vehicle_category_code": "D1E",
                    "issue_date": "1991-07-03",
                    "expiry_date": "2024-11-27",
                },
                {
                    "vehicle_category_code": "DE",
                    "issue_date": "1991-07-03",
                    "expiry_date": "2024-11-27",
                },
                {"vehicle_category_code": "AM", "issue_date": "1987-01-09"},
            ],
        }
    },
    "default": {
        "mDL": {
            "family_name": "Jonas",
            "given_name": "Jonaitis",
            "birth_date": "1960-01-06",
            "document_number": "00777777",
            "portrait": "M",
            "driving_privileges": [
                {
                    "vehicle_category_code": "B1",
                    "issue_date": "2019-12-24",
                    "codes": [{"code": "78"}, {"code": "70.CND"}],
                },
                {
                    "vehicle_category_code": "B",
                    "issue_date": "2019-12-24",
                    "codes": [{"code": "78"}, {"code": "70.CND"}],
                },
                {
                    "vehicle_category_code": "AM",
                    "issue_date": "2019-12-24",
                    "codes": [{"code": "70.CND"}],
                },
            ],
        }
    },
}

from alembic import command


def test_the_migrations_match_the_models(make_app, alembic_config):
    make_app()
    # Fails when a model changes without a migration. Create one with
    # "uv run alembic revision --autogenerate -m '...'", review it and commit it.
    command.check(alembic_config)


def test_the_migrations_can_be_undone_and_redone(make_app, alembic_config):
    make_app()
    command.downgrade(alembic_config, "base")
    command.upgrade(alembic_config, "head")

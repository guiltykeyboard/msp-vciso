-- Development-only login provisioning. Production deployments must inject
-- unique credentials through their secret manager and provision equivalent
-- NOBYPASSRLS runtime roles outside application migrations.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'watchtower_app') then
    create role watchtower_app
      nologin nosuperuser nocreatedb nocreaterole noinherit nobypassrls;
  end if;

  if not exists (select 1 from pg_roles where rolname = 'watchtower_runtime') then
    create role watchtower_runtime
      login password 'watchtower_dev_password'
      nosuperuser nocreatedb nocreaterole inherit nobypassrls;
  end if;

  grant watchtower_app to watchtower_runtime;
end
$$;

create extension if not exists pgcrypto;

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  description text not null default 'fixture'
);
alter table public.invoices enable row level security;
grant select, insert, update, delete on public.invoices to authenticated;
create policy "authenticated can do everything" on public.invoices for all to authenticated using (true) with check (true);

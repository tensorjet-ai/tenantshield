create extension if not exists pgcrypto;

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  description text not null default 'fixture'
);
create index invoices_org_id_idx on public.invoices (org_id);
alter table public.invoices enable row level security;
grant select, insert, update, delete on public.invoices to authenticated;

create policy "tenant select" on public.invoices for select to authenticated
  using (org_id = ((select auth.jwt() ->> 'org_id')::uuid));
create policy "tenant insert" on public.invoices for insert to authenticated
  with check (org_id = ((select auth.jwt() ->> 'org_id')::uuid));
create policy "tenant update" on public.invoices for update to authenticated
  using (org_id = ((select auth.jwt() ->> 'org_id')::uuid))
  with check (org_id = ((select auth.jwt() ->> 'org_id')::uuid));
create policy "tenant delete" on public.invoices for delete to authenticated
  using (org_id = ((select auth.jwt() ->> 'org_id')::uuid));

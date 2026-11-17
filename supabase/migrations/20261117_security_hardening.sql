-- Security hardening for the shegeftidan Supabase project.
-- Already applied to project gkowvobmhxjyynwuygwm on 2026-11-17.

-- 1. Anonymous visitors could UPDATE any column of a published article via the public API.
--    Remove that policy; counters now change only through the SECURITY DEFINER functions below.
drop policy if exists "sg_articles public counters update" on public.sg_articles;

-- 2. Counter functions run with owner rights (anon no longer has UPDATE on the table).
alter function public.sg_add_view(uuid) security definer;
alter function public.sg_like(uuid, integer) security definer;
revoke execute on function public.sg_add_view(uuid) from public;
revoke execute on function public.sg_like(uuid, integer) from public;
grant execute on function public.sg_add_view(uuid) to anon, authenticated;
grant execute on function public.sg_like(uuid, integer) to anon, authenticated;

-- 3. Remove broad table privileges (TRUNCATE, REFERENCES, TRIGGER, UPDATE on everything).
--    RLS still applies to whatever is granted below.
revoke all on all tables in schema public from anon, authenticated;

grant select on public.sg_articles, public.sg_categories to anon, authenticated;
grant insert, update, delete on public.sg_articles, public.sg_categories to authenticated;
grant select, insert on public.sg_comments to anon;
grant select, insert, update on public.sg_comments to authenticated;
grant select on public.sg_admins to authenticated;

-- Legacy tables used by the Rubika import (policies already restrict writes to admins).
grant select on public.posts, public.categories to anon, authenticated;
grant insert, update, delete on public.posts to authenticated;
grant select on public.admin_users to authenticated;

-- 4. Public storage buckets allowed ANY signed-in user to upload files.
--    The Rubika webhook uses the service role, so it is not affected.
drop policy if exists "Authenticated Upload" on storage.objects;

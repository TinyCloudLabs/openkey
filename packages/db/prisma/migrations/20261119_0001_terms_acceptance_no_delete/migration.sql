-- TC-3232: an acceptance goes only with its account. A row-level delete is refused while the account still
-- exists; deleting the account still removes its rows through the ON DELETE CASCADE (the account row is gone
-- by the time the cascade deletes them). TRUNCATE is not covered.
CREATE FUNCTION refuse_terms_acceptance_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM "user" WHERE id = OLD."userId") THEN
    RAISE EXCEPTION 'terms acceptance is append-only';
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER terms_acceptance_no_delete BEFORE DELETE ON "terms_acceptance"
  FOR EACH ROW EXECUTE FUNCTION refuse_terms_acceptance_delete();

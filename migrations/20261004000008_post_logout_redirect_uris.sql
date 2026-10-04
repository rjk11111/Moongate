-- Where a client may send the browser after RP-initiated logout. Exact values,
-- separate from login redirect URIs so one can never stand in for the other.
CREATE TABLE client_post_logout_redirect_uris (
    client_id    text NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);

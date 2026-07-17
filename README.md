# Beer Bible API

## Description

This is the server side component of the "Beer Bible" web application that provides users with access to information about beers within their brewery.
The database requires authentication and authorization using basic HTTP authentication and JWT (token-based) authentication.

![screenshot of live Beer Bible API being tested in Postman](https://user-images.githubusercontent.com/96999730/237748289-bfc248cf-e89e-40b4-8a75-ef9a66bae3b1.png)

## Built With

MERN stack

- MongoDB
- Express
- React
- Node.js

## Technical Requirements

- MongoDB
- node.js, usage of package.json
- Express
- RESTful architecture
- usage of at least three middleware modules
- database: built with MongoDB
- business logic layer: modeled with Mongoose
- API return movies in JSON
- testing in Postman
- security measures: code for user authentication, user authorization, data validation, meet data security regulations (GDPO)
- Deployment on Heroku

## Invite Security Cutover

The compatibility frontend only allows old invite links to keep working before the backend cutover is complete. After the migration is applied and the backend is deployed, legacy links are intentionally tombstoned with `410 Gone`; the brewery manager must resend a fresh invite. Legacy invites that are not bound to a normalized `recipientEmail` are intentionally rejected during acceptance. The coordinated cutover is:

1. Deploy the compatibility frontend first.
2. Freeze invite sends plus user creation and any other normalization-relevant writes before running the migration. This freeze is operational only; the backend does not enforce it automatically at runtime.
3. Run `npm run migrate:invites-security` in dry-run mode in the target environment and review the audit counts.
4. Resolve any reported invalid or duplicate canonical user-email groups and any duplicate invite-token groups before applying.
5. Apply in the target environment with `npm run migrate:invites-security -- --apply`. If `NODE_ENV=production`, apply requires `npm run migrate:invites-security -- --apply --confirm-production`. Dry-run remains allowed in production.
6. Deploy the backend with automatic Mongoose index creation disabled so the explicit migration remains the only index writer during rollout.
7. Unfreeze writes and resend fresh invites for any revoked legacy or duplicate outstanding records.

The migration runs in dry-run mode by default, never prints the raw Mongo connection string, allows production dry-runs, requires both `--apply` and `--confirm-production` before applying in `NODE_ENV=production`, audits canonical user emails before creating the unique user-email index, revokes all conflicting outstanding invites for resend, normalizes only collision-free emails during apply, and reconciles the relevant invite and user indexes. Safe production rollout order is: compatibility frontend deploy, explicit write freeze, production dry-run, collision cleanup, apply with both flags, backend deploy, then unfreeze and resend revoked legacy invites. Once the migration and backend deploy are complete, legacy invite links should no longer be accepted and should return `410 Gone` until a brewery manager resends a current invite.

# Intégration native Kyros SSO v4

Aegis utilise le contrat Kyros SSO v4 directement. Il ne s’agit pas d’un
client OpenID Connect générique : `KYROS_ISSUER=kyros` est un identifiant de
jeton et non une URL. La découverte est toujours chargée depuis
`{KYROS_BASE_URL}/.well-known/kyros-configuration`.

L’implémentation se trouve dans `internal/auth/kyros.go`; les routes de départ
et de callback sont dans `internal/api/handlers_auth.go`.

## Garanties implémentées

- Authorization Code avec PKCE S256.
- Pushed Authorization Requests (PAR), obligatoire avant la redirection.
- Handshake `kyros_sso_version`, `kyros_edition` et
  `kyros_application_scope` envoyé à `/par` et `/token`.
- `state` aléatoire stocké haché, valable dix minutes et consommable une fois.
- Vérification du paramètre `iss` de la réponse d’autorisation.
- Validation de l’access token avec une clé `kid` du JWKS et uniquement
  l’algorithme RS256.
- Vérification obligatoire de `iss`, `aud`, `resource_aud`, `client_id`,
  `sub`, `exp`, `nbf`, `sso_version=v4` et de chaque scope requis.
- Liaison du compte sur `sub`, jamais sur l’adresse e-mail.
- Création d’une session Aegis locale après validation ; aucun token Kyros
  n’est conservé dans la session ou en base.
- Aucun secret, code ou token n’est inclus dans les réponses, audits ou logs.
- Le login local reste indépendant et disponible quand Kyros est indisponible.

## Configuration

```ini
AUTH_PROVIDER=kyros
KYROS_SSO_VERSION=v4
KYROS_BASE_URL=https://kyros.example.com
KYROS_CLIENT_ID=aegis-panel
KYROS_CLIENT_SECRET=<secret fourni par Kyros>
KYROS_ISSUER=kyros
KYROS_AUDIENCE=kyros-modules
KYROS_RESOURCE_AUDIENCE=kyros:sso:aegis
KYROS_REQUESTED_SCOPE=profile email
KYROS_REQUIRED_SCOPES=profile email
KYROS_EDITION=standard
KYROS_APPLICATION_SCOPE=standard
KYROS_TIMEOUT_SECONDS=5
KYROS_AUTHORIZE_URL=https://kyros.example.com/authorize
KYROS_TOKEN_URL=https://kyros.example.com/token
KYROS_PAR_URL=https://kyros.example.com/par
KYROS_JWKS_URL=https://kyros.example.com/sso/v4/jwks
```

Les quatre URL d’endpoint peuvent être laissées vides : Aegis utilise alors
les valeurs publiées par la découverte Kyros. Lorsqu’elles sont renseignées,
elles servent d’override explicite. La découverte reste obligatoire afin de
confirmer le support de SSO v4, PKCE S256 et RS256.

L’URI de callback n’ajoute pas de variable Kyros spécifique. Elle est dérivée
de `AEGIS_PUBLIC_URL` :
`https://<domaine>/api/v1/auth/kyros/callback`. Elle doit être enregistrée à
l’identique dans Kyros.

`KYROS_CLIENT_SECRET` peut rester vide pour un client public autorisé par
Kyros. En production, conserver les secrets dans `/etc/aegis/aegis.env` avec
les permissions prévues par l’installateur.

Le fournisseur est activé uniquement avec `AUTH_PROVIDER=kyros`. Garder
`AEGIS_LOCAL_AUTH_ENABLED=true` fournit le secours local recommandé.

## Déroulement

1. `GET /api/v1/auth/kyros/start?next=/devices` génère `state`, le verifier
   PKCE et le challenge S256.
2. Aegis envoie ces données et le handshake Kyros au endpoint PAR.
3. Le navigateur est redirigé vers
   `/authorize?client_id=…&request_uri=…`; les données sensibles du PAR ne
   sont pas répétées dans l’URL.
4. Au callback, Aegis consomme `state`, vérifie l’issuer de réponse, puis
   échange le code avec le verifier PKCE et le handshake v4.
5. L’access token est vérifié en RS256 via le JWKS. Tous les claims et scopes
   obligatoires sont contrôlés avant d’utiliser l’identité.
6. Aegis trouve ou crée l’utilisateur lié à `sub`, émet sa session locale et
   redirige vers le chemin `next` préalablement validé.

## Rôles et cycle de vie

Les rôles ou groupes Kyros ne sont pas importés. Un nouvel utilisateur Kyros
reçoit le rôle Aegis `user`; les droits administrateur restent gérés dans
Aegis. La déconnexion ferme la session Aegis. Les access/refresh tokens Kyros
ne sont ni stockés ni renouvelés, puisque seule la session locale est utilisée
après la connexion.

## Vérifications de mise en production

1. Vérifier que la découverte annonce `v4`, `S256`, PAR, un JWKS et `RS256`.
2. Confirmer l’URI de callback exacte et les trois valeurs
   client/audiences avec l’enregistrement Kyros.
3. Tester le parcours avec un utilisateur possédant tous les scopes requis,
   puis avec un scope manquant.
4. Tester une rotation de clé JWKS : Aegis recharge immédiatement le JWKS si
   le `kid` reçu n’est pas dans son cache de cinq minutes.
5. Couper Kyros et confirmer que le login local reste utilisable et que les
   tunnels existants ne sont pas affectés.

Les tests unitaires utilisent un faux serveur Kyros v4 et une vraie paire RSA.
Un test bout en bout contre l’instance Kyros de production reste nécessaire.

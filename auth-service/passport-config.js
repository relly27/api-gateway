const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const db = require('./db');

if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        let user;

        if (userResult.rows.length === 0) {
          const newUserResult = await db.query(
            'INSERT INTO users (email) VALUES ($1) RETURNING id, email',
            [email]
          );
          user = newUserResult.rows[0];
          const roleResult = await db.query('SELECT id FROM roles WHERE name = $1', ['user']);
          if (roleResult.rows.length > 0) {
            await db.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [user.id, roleResult.rows[0].id]);
          }
        } else {
          user = userResult.rows[0];
        }

        const providerResult = await db.query('SELECT id FROM providers WHERE name = $1', ['google']);
        const providerId = providerResult.rows[0].id;

        const userProviderResult = await db.query(
          'SELECT * FROM user_providers WHERE user_id = $1 AND provider_id = $2',
          [user.id, providerId]
        );

        if (userProviderResult.rows.length === 0) {
          await db.query(
            'INSERT INTO user_providers (user_id, provider_id, provider_user_id) VALUES ($1, $2, $3)',
            [user.id, providerId, profile.id]
          );
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));
}

if (process.env.GITHUB_CLIENT_ID) {
  passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails ? profile.emails[0].value : `${profile.username}@github.com`;
        let userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        let user;

        if (userResult.rows.length === 0) {
          const newUserResult = await db.query(
            'INSERT INTO users (email) VALUES ($1) RETURNING id, email',
            [email]
          );
          user = newUserResult.rows[0];
          const roleResult = await db.query('SELECT id FROM roles WHERE name = $1', ['user']);
          if (roleResult.rows.length > 0) {
            await db.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [user.id, roleResult.rows[0].id]);
          }
        } else {
          user = userResult.rows[0];
        }

        const providerResult = await db.query('SELECT id FROM providers WHERE name = $1', ['github']);
        const providerId = providerResult.rows[0].id;

        const userProviderResult = await db.query(
          'SELECT * FROM user_providers WHERE user_id = $1 AND provider_id = $2',
          [user.id, providerId]
        );

        if (userProviderResult.rows.length === 0) {
          await db.query(
            'INSERT INTO user_providers (user_id, provider_id, provider_user_id) VALUES ($1, $2, $3)',
            [user.id, providerId, profile.id]
          );
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));
}

module.exports = passport;

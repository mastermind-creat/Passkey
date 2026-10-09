'use strict';

const bcrypt = require('bcryptjs');
const { supabase } = require('../config/db');

const mapUser = (row) => row && ({
  id: row.id,
  username: row.username,
  email: row.email,
  password: row.password_hash,
  webAuthnUserID: row.webauthn_user_id,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const findById = async (id) => {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .maybeSingle();
  if (error) throw error;
  return mapUser(data);
};

const findByEmail = async (email) => {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .maybeSingle();
  if (error) throw error;
  return mapUser(data);
};

const findByUsername = async (username) => {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .maybeSingle();
  if (error) throw error;
  return mapUser(data);
};

const findByEmailOrUsername = async (email, username) => {
  const [emailMatch, usernameMatch] = await Promise.all([
    supabase.from('users').select('id').eq('email', email).maybeSingle(),
    supabase.from('users').select('id').eq('username', username).maybeSingle(),
  ]);
  if (emailMatch.error) throw emailMatch.error;
  if (usernameMatch.error) throw usernameMatch.error;
  return Boolean(emailMatch.data || usernameMatch.data);
};

const create = async ({ username, email, password, webAuthnUserID }) => {
  const passwordHash = password ? await bcrypt.hash(password, 12) : null;
  const { data, error } = await supabase
    .from('users')
    .insert({
      username,
      email,
      password_hash: passwordHash,
      webauthn_user_id: webAuthnUserID,
    })
    .select('*')
    .single();
  if (error) throw error;
  return mapUser(data);
};

const comparePassword = (user, plain) => {
  if (!user.password) return Promise.resolve(false);
  return bcrypt.compare(plain, user.password);
};

module.exports = {
  findById,
  findByEmail,
  findByUsername,
  findByEmailOrUsername,
  create,
  comparePassword,
};

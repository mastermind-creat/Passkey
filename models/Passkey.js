'use strict';

const { supabase } = require('../config/db');

const mapPasskey = (row) => row && ({
  id: row.id,
  userId: row.user_id,
  credentialID: row.credential_id,
  credentialPublicKey: row.credential_public_key,
  credentialAlgorithm: row.credential_algorithm,
  counter: row.counter,
  transports: row.transports || [],
  deviceName: row.device_name,
  lastUsedAt: row.last_used_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const listForUser = async (userId) => {
  const { data, error } = await supabase
    .from('passkeys')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: true });
  if (error) throw error;
  return data.map(mapPasskey);
};

const create = async ({
  userId,
  credentialID,
  credentialPublicKey,
  credentialAlgorithm,
  counter,
  transports,
  deviceName,
}) => {
  const { data, error } = await supabase
    .from('passkeys')
    .insert({
      user_id: userId,
      credential_id: credentialID,
      credential_public_key: credentialPublicKey,
      credential_algorithm: credentialAlgorithm,
      counter,
      transports,
      device_name: deviceName,
    })
    .select('*')
    .single();
  if (error) throw error;
  return mapPasskey(data);
};

const findByCredentialID = async (credentialID) => {
  const { data, error } = await supabase
    .from('passkeys')
    .select('*')
    .eq('credential_id', credentialID)
    .maybeSingle();
  if (error) throw error;
  return mapPasskey(data);
};

const updateAuthentication = async (id, counter, lastUsedAt) => {
  const { error } = await supabase
    .from('passkeys')
    .update({ counter, last_used_at: lastUsedAt })
    .eq('id', id);
  if (error) throw error;
};

const renameOwned = async (id, userId, deviceName) => {
  const { data, error } = await supabase
    .from('passkeys')
    .update({ device_name: deviceName })
    .eq('id', id)
    .eq('user_id', userId)
    .select('device_name')
    .maybeSingle();
  if (error) throw error;
  return data ? data.device_name : null;
};

const deleteOwned = async (id, userId) => {
  const { data, error } = await supabase
    .from('passkeys')
    .delete()
    .eq('id', id)
    .eq('user_id', userId)
    .select('id')
    .maybeSingle();
  if (error) throw error;
  return Boolean(data);
};

module.exports = {
  listForUser,
  create,
  findByCredentialID,
  updateAuthentication,
  renameOwned,
  deleteOwned,
};

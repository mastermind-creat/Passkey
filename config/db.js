'use strict';

const { createClient } = require('@supabase/supabase-js');

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured.');
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

const connectDB = async () => {
  const { error } = await supabase.from('users').select('id').limit(1);
  if (error) {
    throw new Error(`Supabase connection failed: ${error.message}`);
  }
  console.log('Supabase connected');
};

module.exports = { supabase, connectDB };

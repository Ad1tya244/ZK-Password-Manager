import * as argon2 from "argon2";

export interface HashResult {
  hash: string;
  salt: string;
}

export const hashPassword = async (password: string): Promise<HashResult> => {
  // Argon2 automatically generates a salt. We can extract it or just store the hash which contains the salt.
  // Requirement says "Unique salt per user". Argon2 does this by default.
  // The hash string from argon2.hash() includes the parameters, salt, and hash.
  // However, if we want to store salt separately as per schema `salt` column:
  // We can't easily extract the raw salt from the formatted string without parsing.
  // But typically with Argon2, storing the full hash string is enough.
  // To satisfy the specific schema requirement of a separate salt column, 
  // we might need to manually generate a salt or just duplicate it?
  // Actually, let's stick to standard Argon2 best practices but fill the salt column 
  // with something meaningful or the extracted salt if possible.
  // Argon2.hash returns a string. 
  
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
  });

  // For the 'salt' column, we can store the salt if we used a manual one, 
  // but argon2 generates it. 
  // Let's create a random salt just to populate the column and use it if needed, 
  // but Argon2 encodes its used salt in the hash. 
  // If we MUST use a separate salt to hash, we can pass it to argon2 options.
  // However, argon2 node library manages salt better.
  // Let's assume the 'salt' column is for metadata or legacy reasons if the user insists,
  // OR we generate a salt manually and pass it to argon2.
  // Let's generate a salt manually to satisfy "Unique salt per user" explicitly and store it.
  
  // Actually, argon2 package recommends letting it handle salt. 
  // Parsing the salt from the hash:
  // The hash format is $argon2id$v=19$m=65536,t=3,p=4$salt$hash
  // We can extract it.
  
  const parts = hash.split('$');
  const salt = parts[4] || ""; 

  return { hash, salt };
};

export const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return await argon2.verify(hash, password);
};

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use bip39::Mnemonic;
use bitcoin::{
    Address, Network, PublicKey,
    bip32::{DerivationPath, Xpriv},
    key::Secp256k1,
};

use thiserror::Error;

type PathStr = String;

#[derive(Debug, Error)]
pub enum MatcherError {
    #[error("Derivation path is unexpectedly invalid, derivation path: {0}")]
    Derivation(PathStr),

    #[error("Failed to create extended private key, error: {0}")]
    PrivKey(String),

    #[error("Failed to inplace-modify path string index: {0}")]
    PathStrModify(PathStr),
}

impl MatcherError {
    pub fn from_derivation_path(path: &str) -> MatcherError {
        MatcherError::Derivation(path.to_string())
    }
}

/// A derivation standard encapsulates the base derivation path used for key derivation
/// and the expected address prefix that results from using that standard.
///
/// For instance, legacy addresses use the base path `"m/44'/0'/0'/0/"` and expect addresses starting with `"1"`,
/// whereas native SegWit addresses use `"m/84'/0'/0'/0/"` with addresses beginning with `"bc1q"`.
///
/// # Examples
///
/// ```
/// use bit_digger::matcher::DerivationStandard;
///
/// let standard = DerivationStandard::new("m/44'/0'/0'/0/", "1");
/// assert_eq!(standard.base_path, "m/44'/0'/0'/0/");
/// assert_eq!(standard.starts_with, "1");
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct DerivationStandard<'a, 'b> {
    /// The base derivation path used to generate keys.
    /// Must have an ending back slash, i.e.
    /// ```
    /// let valid_base_path = "m/44'/0'/0'/0/";
    /// ```
    pub base_path: &'a str,
    /// The expected starting string/prefix for addresses generated with this standard.
    pub starts_with: &'b str,
}

pub const SUPPORTED_STANDARDS: [DerivationStandard; 4] = [
    DerivationStandard {
        base_path: "m/44'/0'/0'/0/", // Legacy
        starts_with: "1",
    },
    DerivationStandard {
        base_path: "m/49'/0'/0'/0/", // SegWit
        starts_with: "3",
    },
    DerivationStandard {
        base_path: "m/84'/0'/0'/0/", // Native SegWit
        starts_with: "bc1q",
    },
    DerivationStandard {
        base_path: "m/86'/0'/0'/0/", // Taproot
        starts_with: "bc1p",
    },
];

impl DerivationStandard<'_, '_> {
    /// Returns a derivation standard with the given base path and expected address prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use bit_digger::matcher::DerivationStandard;
    /// let standard = DerivationStandard::new("m/44'/0'/0'/0/", "1");
    /// ```
    pub fn new<'a, 'b>(base_path: &'a str, starts_with: &'b str) -> DerivationStandard<'a, 'b> {
        DerivationStandard {
            base_path,
            starts_with,
        }
    }

    /// Returns a reference to derivation standard if the address starts with a supported prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use bit_digger::matcher::DerivationStandard;
    /// let standard = DerivationStandard::from_address("1BvB...");
    /// assert_eq!(standard.unwrap().base_path, "m/44'/0'/0'/0/");
    /// ```
    pub fn from_address(address: &str) -> Option<&DerivationStandard> {
        for standard in SUPPORTED_STANDARDS.iter() {
            if address.starts_with(standard.starts_with) {
                return Some(standard);
            }
        }

        None
    }

    /// Converts the provided derivation path and extended private key into a Bitcoin address
    ///
    /// # Errors
    ///
    /// Returns a `MatcherError` if key derivation fails or if a public key cannot be properly compressed.
    ///
    /// # Examples
    ///
    /// See examples in Matcher::generate_addresses
    pub fn into_address(
        &self,
        path: &DerivationPath,
        xpriv: &Xpriv,
    ) -> Result<String, MatcherError> {
        let secp = Secp256k1::new();

        let child_xpriv = xpriv
            .derive_priv(&secp, path)
            .map_err(|_| MatcherError::PrivKey("Failed to derive child key".to_string()))?;

        // Get the secp256k1 public key and convert it to bitcoin::PublicKey.
        let child_secp_pubkey = child_xpriv.private_key.public_key(&secp);
        let child_pubkey = PublicKey::new(child_secp_pubkey);

        match self.starts_with {
            "1" => {
                // Legacy P2PKH address.
                Ok(Address::p2pkh(child_pubkey, Network::Bitcoin).to_string())
            }
            "3" => {
                // For P2SH-wrapped segwit addresses.
                use bitcoin::CompressedPublicKey;
                let cp =
                    CompressedPublicKey::from_slice(&child_pubkey.to_bytes()).map_err(|_| {
                        MatcherError::PrivKey("Unable to compress public key".to_string())
                    })?;
                Ok(Address::p2shwpkh(&cp, Network::Bitcoin).to_string())
            }
            "bc1q" => {
                // For native SegWit (bech32) addresses.
                use bitcoin::CompressedPublicKey;

                let cp: bitcoin::CompressedPublicKey =
                    CompressedPublicKey::from_slice(&child_pubkey.to_bytes()).map_err(|_| {
                        MatcherError::PrivKey("Unable to compress public key".to_string())
                    })?;
                Ok(Address::p2wpkh(&cp, Network::Bitcoin).to_string())
            }
            "bc1p" => {
                // For Taproot addresses. p2tr takes the secp context, an untweaked internal key,
                // an optional script tree (here None), and the network.
                Ok(
                    Address::p2tr(&secp, child_pubkey.inner.into(), None, Network::Bitcoin)
                        .to_string(),
                )
            }
            _ => {
                // Fallback to legacy P2PKH address.
                Ok(Address::p2pkh(child_pubkey, Network::Bitcoin).to_string())
            }
        }
    }

    /// Returns a derivation standard if the address starts with a supported prefix.
    pub fn from_prefix(prefix: &str) -> Option<&DerivationStandard> {
        for standard in SUPPORTED_STANDARDS.iter() {
            if prefix.starts_with(standard.starts_with) {
                return Some(standard);
            }
        }

        None
    }
    /// Returns a slice of supported derivation standards.
    pub fn get_supported_standards() -> &'static [DerivationStandard<'static, 'static>] {
        &SUPPORTED_STANDARDS
    }
}

/// Helper function to inplace modify path index
fn modify_path_index(path: &mut String, index: usize) -> Result<(), MatcherError> {
    let index_str = index.to_string();
    let path_len = path.len();

    let last_slash = match path.rfind('/') {
        Some(pos) => pos,
        None => return Err(MatcherError::PathStrModify(path.to_string())),
    };

    path.replace_range(last_slash + 1..path_len, &index_str);

    Ok(())
}

/// The Matcher struct holds references to a set of Bitcoin addresses and a collection of mnemonic
/// phrases. It generates addresses from mnemonics using derivation standards and checks whether
/// they match addresses in its stored set. This can be useful, for example, to verify wallet addresses
/// or scan for address matches.
///
/// # Fields
///
/// - `addrs`: A reference to a HashSet of Bitcoin addresses (each represented as a String).
/// - `mnems`: A reference to a Vec of mnemonic phrases (from bip39) used for key derivation.
/// - `logging`: A boolean flag to enable or disable logging during operations.
pub struct Matcher<'a, 'b> {
    pub addrs: &'a HashSet<String>,
    pub mnems: &'b [Mnemonic],
    pub logging: bool,
}

impl<'a, 'b> Matcher<'a, 'b> {
    /// Creates a new Matcher instance.
    ///
    /// # Arguments
    ///
    /// * `addrs` - A reference to the set of Bitcoin addresses to match against.
    /// * `mnems` - A reference to the vector of mnemonic phrases used for deriving keys.
    /// * `logging` - A flag specifying whether logging should be enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{
    ///     collections::HashSet,
    ///     str::FromStr,
    /// };
    /// use bip39::Mnemonic;
    /// use bit_digger::matcher::Matcher;
    ///
    /// let addresses: HashSet<String> = ["1BGLgRL7EiFxS9H616bfoJPjSugKudECCn"]
    ///     .iter()
    ///     .map(|s| s.to_string())
    ///     .collect();
    /// let mnem = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    /// let mnems = vec![mnem];
    ///
    /// let matcher = Matcher::new(&addresses, &mnems, false);
    /// // matcher now holds references to the addresses set and mnemonic vector.
    /// ```
    pub fn new(
        addrs: &'a HashSet<String>,
        mnems: &'b [Mnemonic],
        logging: bool,
    ) -> Matcher<'a, 'b> {
        Matcher {
            addrs,
            mnems,
            logging,
        }
    }

    /// Matches generated addresses against the stored addresses.
    ///
    /// This method generates addresses for each mnemonic by using the provided derivation amounts.
    /// If `amount` is None, it automatically infers how many addresses to generate based on the
    /// stored addresses and supported derivation standards. Then it returns a map of each mnemonic
    /// reference to the vector of addresses (as Strings) that were found in the matcher's address set.
    ///
    /// # Arguments
    ///
    /// * `addr_to_gen_per_mnem` - The total number of addresses to generate per mnemonic.
    /// * `amount` - An optional vector of tuples of the form `(DerivationStandard, usize)` specifying
    ///   the number of addresses to generate for each derivation standard.
    ///
    /// # Returns
    ///
    /// A `HashMap` mapping each mnemonic (by reference) to a Vec of matching Bitcoin addresses.
    ///
    /// # Errors
    ///
    /// Returns a `MatcherError` if key derivation or address generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{
    ///     collections::HashSet,
    ///     str::FromStr,
    /// };
    /// use bip39::Mnemonic;
    /// use bit_digger::matcher::{Matcher, DerivationStandard};
    ///
    /// let addresses: HashSet<String> = ["1BGLgRL7EiFxS9H616bfoJPjSugKudECCn"].iter()
    ///     .map(|s| s.to_string())
    ///     .collect();
    ///
    /// let mnem = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    /// let mnems = vec![mnem];
    /// let matcher = Matcher::new(&addresses, &mnems, false);
    ///
    /// let amount = vec![
    ///     (DerivationStandard::new("m/44'/0'/0'/0/", "1"), 10),
    ///     (DerivationStandard::new("m/49'/0'/0'/0/", "3"), 10),
    ///     (DerivationStandard::new("m/84'/0'/0'/0/", "bc1q"), 10),
    /// ];
    ///
    /// let result = matcher.match_in(30, Some(amount)).unwrap();
    /// // The result maps the mnemonic to its matched addresses.
    /// ```
    pub fn match_in(
        &self,
        addr_to_gen_per_mnem: usize,
        amount: Option<Vec<(DerivationStandard, usize)>>,
    ) -> Result<HashMap<&Mnemonic, Vec<String>>, MatcherError> {
        let amount = match amount {
            Some(amount) => amount,
            None => {
                let mut unmatched_addresses = vec![];

                let mut standards = DerivationStandard::get_supported_standards()
                    .iter()
                    .map(|s| (s.clone(), 0))
                    .collect::<Vec<(DerivationStandard, usize)>>();

                if self.logging {
                    println!("Starting automatic derivation amount inference");
                }

                for addr in self.addrs.iter() {
                    let standard = match DerivationStandard::from_address(addr) {
                        Some(s) => s,
                        None => {
                            unmatched_addresses.push(addr);
                            continue;
                        }
                    };

                    standards
                        .iter_mut()
                        .find(|s| s.0 == *standard)
                        .map(|s| s.1 += 1);
                }

                let total = standards.iter().fold(0, |acc, s| acc + s.1);

                for standard in standards.iter_mut() {
                    standard.1 = (standard.1 as f64 / total as f64 * addr_to_gen_per_mnem as f64)
                        .ceil() as usize;
                }

                if self.logging {
                    println!(
                        "Found {} addresses whose standard is not supported",
                        unmatched_addresses.len()
                    );

                    for standard in standards.iter() {
                        println!("Standard: {}, Amount: {}", standard.0.base_path, standard.1);
                    }
                }

                standards
            }
        };

        let mut found = HashMap::new();

        for (index, mnemonic) in self.mnems.iter().enumerate() {
            let addresses = Self::generate_addresses(&amount, mnemonic)?;

            for addr in addresses {
                if self.addrs.contains(&addr) {
                    if self.logging {
                        println!("Found address {} for mnemonic {:?}", addr, mnemonic);
                    }
                    found.entry(mnemonic).or_insert(vec![]).push(addr);
                }
            }

            if self.logging && (self.mnems.len() / 10 > 0) && index % (self.mnems.len() / 10) == 0 {
                println!(
                    "Processed {}% of the mnemonics ({}/{})",
                    index * 100 / self.mnems.len(),
                    index,
                    self.mnems.len()
                );
            }
        }

        Ok(found)
    }

    /// Generates Bitcoin addresses from a mnemonic seed using the specified derivation standards.
    ///
    /// For each tuple in `amount` (which consists of a `DerivationStandard` and a count), this method
    /// modifies the derivation path by appending the index and derives the corresponding Bitcoin address
    /// using BIP32/BIP39. The generated addresses are returned as a vector of Strings.
    ///
    /// # Arguments
    ///
    /// * `amount` - A slice of tuples specifying for each derivation standard (and its base path)
    ///   how many addresses to generate.
    /// * `mnemonic` - The mnemonic seed used to derive keys and generate addresses.
    ///
    /// # Returns
    ///
    /// A Vec of generated Bitcoin addresses (as Strings).
    ///
    /// # Errors
    ///
    /// Returns a `MatcherError` if key derivation or address generation fails.
    ///
    /// /// # Examples
    ///
    /// ```
    /// use bip39::Mnemonic;
    /// use bit_digger::matcher::{Matcher, DerivationStandard};
    /// use std::str::FromStr;
    ///
    /// let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    /// let amount = vec![
    ///     (DerivationStandard::new("m/44'/0'/0'/0/", "1"), 10),
    ///     (DerivationStandard::new("m/49'/0'/0'/0/", "3"), 10),
    ///     (DerivationStandard::new("m/84'/0'/0'/0/", "bc1q"), 10),
    /// ];
    ///
    /// let addresses = Matcher::generate_addresses(&amount, &mnemonic).unwrap();
    /// // addresses now holds the generated Bitcoin addresses.
    /// ```
    pub fn generate_addresses(
        amount: &[(DerivationStandard, usize)],
        mnemonic: &Mnemonic,
    ) -> Result<Vec<String>, MatcherError> {
        let mut addresses = vec![];
        let seed = mnemonic.to_seed("");
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)
            .map_err(|_| MatcherError::PrivKey("Failed to create master key".to_string()))?;

        for (ds, n) in amount {
            let mut base_path: String = ds.base_path.to_string();
            base_path.reserve(n.to_string().len() + 10);

            for i in 0..*n {
                modify_path_index(&mut base_path, i)?;

                let path = DerivationPath::from_str(&base_path)
                    .map_err(|_| MatcherError::from_derivation_path(base_path.as_str()))?;

                let address = ds.into_address(&path, &xpriv)?;

                addresses.push(address);
            }
        }

        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use std::collections::HashSet;

    #[test]
    fn test_modify_path_index() {
        let mut path = "m/44'/0'/0'/0/".to_string();
        modify_path_index(&mut path, 1).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/1");
        modify_path_index(&mut path, 32).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/32");

        let mut path = "m/44'/0'/0'/0/".to_string();
        modify_path_index(&mut path, 10).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/10");
        modify_path_index(&mut path, 100).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/100");
        modify_path_index(&mut path, 0).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/0");

        let mut path = "m/44'/0'/0'/0/".to_string();
        modify_path_index(&mut path, 100).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/100");
        modify_path_index(&mut path, 1000).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/1000");
        modify_path_index(&mut path, 1).unwrap();
        assert_eq!(path, "m/44'/0'/0'/0/1");
    }

    #[test]
    fn test_derivation_standard_from_address() {
        let standard = DerivationStandard::from_address("1BvB...");
        assert_eq!(standard.unwrap().base_path, "m/44'/0'/0'/0/");

        let standard = DerivationStandard::from_address("3J98...");
        assert_eq!(standard.unwrap().base_path, "m/49'/0'/0'/0/");

        let standard = DerivationStandard::from_address("bc1qar0s...");
        assert_eq!(standard.unwrap().base_path, "m/84'/0'/0'/0/");

        let standard = DerivationStandard::from_address("bc1par0s...");
        assert_eq!(standard.unwrap().base_path, "m/86'/0'/0'/0/");
    }

    #[test]
    fn test_derivation_standard_from_prefix() {
        let standard = DerivationStandard::from_prefix("1");
        assert_eq!(standard.unwrap().base_path, "m/44'/0'/0'/0/");

        let standard = DerivationStandard::from_prefix("3");
        assert_eq!(standard.unwrap().base_path, "m/49'/0'/0'/0/");

        let standard = DerivationStandard::from_prefix("bc1q");
        assert_eq!(standard.unwrap().base_path, "m/84'/0'/0'/0/");

        let standard = DerivationStandard::from_prefix("bc1p");
        assert_eq!(standard.unwrap().base_path, "m/86'/0'/0'/0/");
    }

    const MNEMONIC: &str = "method tribe morning flock suit upon salt puppy jar harbor west wealth device tooth bundle expose mansion scrap erupt helmet hurt promote fit hire";
    const LEGACY_ADDRESSES: [&str; 10] = [
        "1BGLgRL7EiFxS9H616bfoJPjSugKudECCn",
        "1Kc48oyfPrTv9UD1Fk61dZkfxgRM83bU46",
        "1MqmuiTTY8tTgBMFiDZSB9UygSnM5X9sd",
        "15VRc3icVAJmrHC2CXQgecnRyUWc1oWVQW",
        "19DosUKX9zQEdAHWaqCvq67pDAVs5AEpck",
        "1CP296asrQ8hZnFP3GUjrpDcfyc71f6u2r",
        "14kNFbSL4Tt67LG5H5p4Cje9CXqJvNKqfT",
        "1E8CV9uRR8GZSuZAZsaFLHwbjKiQGmifqM",
        "12k1o5tyV1HqimC2FWbN7gzktStByJMYma",
        "1DsLE3UoAo98Vwmbi6a7pDKRcmkBB4Txzh",
    ];

    const SEG_WIT_ADDRESSES: [&str; 10] = [
        "38cArkkfxxL7LtVWAwYNcvZTgf3KtDBcD7",
        "37xqCGNb1rTokVVtjBkCoWBLxmAZjXjUyQ",
        "3EXGQZu3GQnFzJLEyx27dxpjuGTenzfDka",
        "3AyVvwN2SvgwFfQPD423jrg7Yw4umwZcWv",
        "38VgHXNcp2wJZg5KVvAFuKSyD7fhGWVoz8",
        "39vHAo5qSVvQj4XWNPJSzbvfhgKZ8PJF7N",
        "36EHh1dKfXTURcR4N69KAHwAKoZuZp28Qi",
        "37cEAoExVS2roXeu3QDVERAACMym8wL29d",
        "32yaS5LmjcavajMcwU7Ebyq3FmXi7o85HT",
        "32R9GYSTMqWrjW5oyX2oM4xzM52eL8J5jt",
    ];

    const NATIVE_SEG_WIT_ADDRESSES: [&str; 10] = [
        "bc1q39ytrq296c6skxvrkd3m64j2fz5keep26q239t",
        "bc1qe3kvt65klvzmnwehshzfv7w08cng6dqd3vfs2a",
        "bc1q0c7qe879lh7x6cyufen7q8kmrf4rmr032u2ykx",
        "bc1qvwn3a4jflzlkrxckjp76jhu5qhl7tjrw09wgc2",
        "bc1qlmprztxqq4a8l8syfsn48u8v4zejmv4d5l3hle",
        "bc1qyg60vy2wgp2sfmt825yu60kg7pg8t6mej8cjkh",
        "bc1qlakvxvjj3raplc4xu678cr8g9kxdj9249gw7tg",
        "bc1qg8e6kkwzmjek4mt4t6lzu5jm6fq8a2f9y9s9pa",
        "bc1qncyyemztujnavnpqv0jpe53yayu0a8nrquztcl",
        "bc1qszrsm6623dz5kf7dc7fyma0zq4enqtm4e8aqlx",
    ];

    const NOT_MATCHING_LEGACY_ADDRESSES: [&str; 10] = [
        "15JcFwxJEEektpqjyQpRWPEHF9DQBX6NLy",
        "1BZkYY2RdM4iLCD7mGuZu5DpGCssst1NuH",
        "1Ga2CrW3unYeU4esEoNxtLanLXbsu4eR9Z",
        "1HSXNFBkrHAH87NPXDMd8fDS9iTJaKUtih",
        "1FqrZNdEs8yk5eV4kTZJzdpHdWbobFk5y4",
        "17aUocSwJBDdQv8u7S7CN7vMMu7BEAJj1D",
        "12GPo6Wih1Ps1MsvZ2Yo8gsRuJMfn4dpXu",
        "14datpqKqjDMoAwsJQWxF7ZeZNgSDMwghC",
        "1G8bC5cDtE3V6niunvd3B8zG9pdQNM8ePw",
        "1KnjQiJjsdFhaPcKaxNPY9xubTHXibLKn6",
    ];

    const NOT_MATCHING_SEGWIT_ADDRESSES: [&str; 10] = [
        "3BnH3FPZ9CpN4RfxxCJXFLt6tzibvYCi9k",
        "3NYZQsjn8vYR4oE9xFdueLVY7ofMpSncEK",
        "39hwATVfL8Nfe9P6ogpFU5xiDoaVPdWZsh",
        "384QcePn5Z9ZixRXJwaaN5ot2ThPedJiMP",
        "35MEXexaZyK6BTtikKxVadVeeVw9HhdMm7",
        "3EScCZRYJjHuPaYvCevV2WCMJaeCoG9H1R",
        "3JR8Y511MxV2cfP7i7wDXMizbnPZVC8zbo",
        "3Ft9CkUDQx5ybvahFuSR7hggruGNeZRhuP",
        "32VWQ66jafP47tE1q7i3aHZo7eYfHyaXHc",
        "35MVo6Q48NUdtxc2dBxzm1SnEgZqXojPfA",
    ];

    const NOT_MATCHING_NATIVE_SEGWIT_ADDRESSES: [&str; 10] = [
        "bc1q6wznd8c7v4pgwaugt5u3u9mfmus7fglpp9ef60",
        "bc1qz9nx30gtl353gmr5ckmd7wg7jlxkmwl5q9dqr8",
        "bc1qrwafwp7mq36zsryg98c45yj96c28qx3puahafp",
        "bc1q560f5kg4me8tp28mpah7gpphhnwe5aa9wxck6e",
        "bc1qumg52ymsm74y065x6n30uxns8dv5ul73trckgt",
        "bc1q3f6swqv7r3prj9l5z9nphld9z5tzgmh3snf4zg",
        "bc1q4z98wwqdjl5drg5esz98lzyf99fzsvyulyr6fy",
        "bc1qp447e30gatvlww4sz2an9ymaugyeemtksw6fa8",
        "bc1q0jvyt5hm42ukh7c3t98st0xmeyeu6w4thhadkp",
        "bc1qlywz7zrwxna4pln0q5xdjpkwxvtnwk8qchz7xd",
    ];

    // TODO: Generate Taproot

    #[test]
    fn test_match_in() {
        let mut total_addresses = 0;

        let mut addresses = HashSet::new();
        let mut mnems = vec![];

        for addr in LEGACY_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        for addr in SEG_WIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        for addr in NATIVE_SEG_WIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        let mnemonic = Mnemonic::from_str(MNEMONIC).unwrap();
        mnems.push(mnemonic);

        let matcher = Matcher::new(&addresses, &mnems, false);

        let amount = vec![
            (DerivationStandard::new("m/44'/0'/0'/0/", "1"), 10),
            (DerivationStandard::new("m/49'/0'/0'/0/", "3"), 10),
            (DerivationStandard::new("m/84'/0'/0'/0/", "bc1q"), 10),
        ];

        let found = matcher.match_in(total_addresses, Some(amount)).unwrap();

        let mut mnemonic_with_addresses = 0;

        for (_mn, addresses) in found {
            assert_eq!(addresses.len(), total_addresses);
            for addr in addresses {
                assert!(matcher.addrs.contains(&addr));
            }
            mnemonic_with_addresses += 1;
        }

        assert_eq!(mnemonic_with_addresses, 1);
    }

    #[test]
    fn test_match_in_auto() {
        let mut total_addresses = 0;

        let mut addresses = HashSet::new();
        let mut mnems = vec![];

        for addr in LEGACY_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        for addr in SEG_WIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        for addr in NATIVE_SEG_WIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        let mnemonic = Mnemonic::from_str(MNEMONIC).unwrap();
        mnems.push(mnemonic);
        let matcher = Matcher::new(&addresses, &mnems, false);
        let found = matcher.match_in(total_addresses, None).unwrap();
        let mut mnemonic_with_addresses = 0;

        for (_mn, addresses) in found {
            assert_eq!(addresses.len(), total_addresses);
            for addr in addresses {
                assert!(matcher.addrs.contains(&addr));
            }
            mnemonic_with_addresses += 1;
        }

        assert_eq!(mnemonic_with_addresses, 1);
    }

    #[test]
    fn test_match_in_no_more_than_real_matches() {
        let mut total_addresses = 0;

        let mut addresses = HashSet::new();
        let mut mnems = vec![];

        for addr in LEGACY_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        for addr in SEG_WIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        for addr in NATIVE_SEG_WIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            total_addresses += 1;
        }

        let mut not_matching_addresses = 0;

        for addr in NOT_MATCHING_LEGACY_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            not_matching_addresses += 1;
        }

        for addr in NOT_MATCHING_SEGWIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            not_matching_addresses += 1;
        }

        for addr in NOT_MATCHING_NATIVE_SEGWIT_ADDRESSES.iter() {
            addresses.insert(addr.to_string());
            not_matching_addresses += 1;
        }

        let mnemonic = Mnemonic::from_str(MNEMONIC).unwrap();
        mnems.push(mnemonic);

        let matcher = Matcher::new(&addresses, &mnems, false);

        let found = matcher
            .match_in(total_addresses + not_matching_addresses, None)
            .unwrap();

        let mut mnemonic_with_addresses = 0;

        for (_mn, addresses) in found {
            assert_eq!(addresses.len(), total_addresses);
            for addr in addresses {
                assert!(matcher.addrs.contains(&addr));
            }
            mnemonic_with_addresses += 1;
        }

        assert_eq!(mnemonic_with_addresses, 1);
    }

    #[test]
    fn test_generate_addresses() {
        let mnemonic = Mnemonic::from_str(MNEMONIC).unwrap();

        let amount = vec![
            (DerivationStandard::new("m/44'/0'/0'/0/", "1"), 10),
            (DerivationStandard::new("m/49'/0'/0'/0/", "3"), 10),
            (DerivationStandard::new("m/84'/0'/0'/0/", "bc1q"), 10),
        ];

        let addresses = Matcher::generate_addresses(&amount, &mnemonic).unwrap();

        for (addr, legacy) in addresses.iter().zip(LEGACY_ADDRESSES.iter()) {
            assert_eq!(addr, legacy);
        }

        for (addr, segwit) in addresses.iter().skip(10).zip(SEG_WIT_ADDRESSES.iter()) {
            assert_eq!(addr, segwit);
        }

        for (addr, native_segwit) in addresses
            .iter()
            .skip(20)
            .zip(NATIVE_SEG_WIT_ADDRESSES.iter())
        {
            assert_eq!(addr, native_segwit);
        }
    }
}

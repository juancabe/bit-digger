use core::time;
use std::{collections::HashSet, hash::BuildHasherDefault, str::FromStr};

use ahash::AHasher;
use bip39::Mnemonic;

pub type AHashBuilder = BuildHasherDefault<AHasher>;

const MIN_WORDS: usize = 12;
const MAX_WORDS: usize = 24;

fn is_invalid_word_count(word_count: usize) -> bool {
    word_count < MIN_WORDS || word_count % 3 != 0 || word_count > MAX_WORDS
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MnemFetchError {
    #[error("Invalid word count: {0}")]
    InvalidWordCount(usize),
}

/// Struct used to fetch mnemonics from different sources
///
/// ## Fields
/// `gen_mnemonics`: A vector of mnemonics that have been generated
/// `wordlist`: A HashSet of all the words in the wordlist used to discover the mnemonics
/// `word_ns`: A vector of the valid mnemonic lengths
///
/// ## Methods
/// `new(lang: bip39::Language) -> Self`: Creates a new MnemFetcher with the given language
/// `add_one(mnemonic: Mnemonic)`: Adds a single mnemonic to the internal collection
/// `set_word_ns(word_ns: Vec<usize>)`: Sets the valid mnemonic lengths
/// `add_from_words(words: &[&str]) -> &[Mnemonic]`: Creates mnemonics from the given words and adds them to the internal collection
pub struct MnemFetcher<'a> {
    pub gen_mnemonics: HashSet<bip39::Mnemonic, AHashBuilder>,
    wordlist: HashSet<&'a str, AHashBuilder>,
    word_ns: Vec<usize>,
    lang: bip39::Language,
}

impl<'a> MnemFetcher<'a> {
    pub fn new(lang: bip39::Language) -> Self {
        let wordlist: HashSet<&'a str, AHashBuilder> =
            lang.word_list().into_iter().map(|w| *w).collect();

        MnemFetcher {
            gen_mnemonics: HashSet::with_hasher(AHashBuilder::default()),
            wordlist,
            word_ns: vec![MIN_WORDS, MAX_WORDS],
            lang,
        }
    }

    /// Just add one already created mnemonic
    pub fn add_one(&mut self, mnemonic: Mnemonic) {
        self.gen_mnemonics.insert(mnemonic);
    }

    /// Set word_ns
    ///
    /// # Description
    /// Sets the valid mnemonic lengths
    ///
    /// # Arguments
    /// - `word_ns`: A vector of the valid mnemonic lengths
    ///
    /// # Returns
    /// - Error with the first invalid word count
    /// - Ok if all word counts are valid
    ///
    /// # Example
    /// ```rust
    /// use bit_digger::mnem_fetch::MnemFetcher;
    /// let mut mf = MnemFetcher::new(bip39::Language::English);
    /// mf.set_word_ns(vec![12, 15, 18, 21, 24]).unwrap();
    /// ```
    pub fn set_word_ns(&mut self, word_ns: Vec<usize>) -> Result<(), MnemFetchError> {
        for wc in word_ns.iter() {
            if is_invalid_word_count(*wc) {
                return Err(MnemFetchError::InvalidWordCount(*wc));
            }
        }

        self.word_ns = word_ns;

        Ok(())
    }

    /// Create mnemonics from `words` and add them to internal collection
    ///
    /// # Description
    /// Tries to create mnemonics from the given words.
    /// - It will take a sequence of n `words` that can generate a valid mnemonic, where n is any of the valid mnemonic lengths, in the given order.
    ///
    /// # Arguments
    /// - `words`: A list of words that should be used to generate the mnemonics.
    ///
    /// # Returns
    /// - It will return a reference to the added mnemonics slice, if no mnemonic was generated the slice will be empty.
    ///
    /// # Example
    /// ```rust
    /// use bit_digger::mnem_fetch::MnemFetcher;
    /// let mut mf = MnemFetcher::new(bip39::Language::English);
    /// let invalid_words = vec![
    ///    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    ///   "absurd", "abuse", "access", "accident",
    /// ];
    /// let mnemonics = mf.add_from_words(&invalid_words);
    /// assert_eq!(mnemonics, 0);
    /// ```
    pub fn add_from_words(&mut self, words: &[&str]) -> usize {
        let mut valid_words_str = String::with_capacity(words.len() * 10); // String that contains all the valid words
        let mut valid_words_start_ptr: Vec<usize> = Vec::with_capacity(words.len()); // Pointer to the start of each (word )
        //                                                                                                                (^    )
        let mut valid_words_end_ptr: Vec<usize> = Vec::with_capacity(words.len()); // Pointer to the end of each (word )
        //                                                                                                       (    ^)

        self.gen_mnemonics.reserve(words.len() / 1000);

        // Construct the words String along with the pointers
        for w in words {
            if !self.wordlist.contains(w) {
                continue;
            }

            valid_words_start_ptr.push(valid_words_str.len());
            valid_words_str.push_str(w);
            valid_words_end_ptr.push(valid_words_str.len());
            valid_words_str.push_str(" ");
        }

        let mut valid_mnemonics = 0;

        for wc in self.word_ns.clone() {
            if wc > valid_words_start_ptr.len() {
                continue;
            }
            for start_at in 0..valid_words_start_ptr.len() - (wc - 1) {
                if self.window_check(
                    &valid_words_str,
                    &valid_words_start_ptr,
                    &valid_words_end_ptr,
                    start_at,
                    wc,
                ) {
                    valid_mnemonics += 1;
                }
            }
        }

        valid_mnemonics
    }

    /// Internal function to check wether a &str slice contains a valid mnemonic of `wc` words
    fn window_check(
        &mut self,
        valid_words: &str,
        valid_words_start_ptr: &[usize],
        valid_words_end_ptr: &[usize],
        start_at: usize,
        wc: usize,
    ) -> bool {
        let start_index = valid_words_start_ptr[start_at];
        let end_index = valid_words_end_ptr[start_at + wc - 1];

        let mnemonic =
            Mnemonic::parse_in_normalized(self.lang, &valid_words[start_index..end_index]);

        if mnemonic.is_ok() {
            self.gen_mnemonics.insert(mnemonic.unwrap());
            return true;
        }

        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_invalid_word_count() {
        assert_eq!(is_invalid_word_count(11), true);
        assert_eq!(is_invalid_word_count(13), true);
        assert_eq!(is_invalid_word_count(25), true);
        assert_eq!(is_invalid_word_count(12), false);
        assert_eq!(is_invalid_word_count(15), false);
        assert_eq!(is_invalid_word_count(24), false);
    }

    const VALID_MNEMONIC: &str = "aware such neglect occur kick large parade crazy ceiling rain afraid mad canyon taxi group";

    #[test]
    fn test_mnem_fetch_add_one() {
        let mut mf = MnemFetcher::new(bip39::Language::English);

        let mnemonic = Mnemonic::from_str(VALID_MNEMONIC).unwrap();
        mf.add_one(mnemonic);

        assert_eq!(mf.gen_mnemonics.len(), 1);
    }

    #[test]
    fn test_mnem_fetch_add_from_words() {
        let mut mf = MnemFetcher::new(bip39::Language::English);
        mf.set_word_ns(vec![12, 15, 18, 21, 24]).unwrap();

        let binding = VALID_MNEMONIC.to_string();
        let mut words = binding.split_whitespace().collect::<Vec<&str>>();

        let mnemonics1 = mf.add_from_words(&words);

        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");

        let mnemonics2 = mf.add_from_words(&words);

        words.reverse();

        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");

        words.reverse();

        let mnemonics3 = mf.add_from_words(&words);

        assert_eq!(mnemonics1, mnemonics2);
        assert_eq!(mnemonics2, mnemonics3);
    }

    #[test]
    fn test_mnem_fetch_add_from_words_invalid_mnemonic() {
        let mut mf = MnemFetcher::new(bip39::Language::English);

        let words = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident",
        ];

        let mnemonics = mf.add_from_words(&words);

        assert_eq!(mnemonics, 0);

        let binding = VALID_MNEMONIC.to_string();
        let mut words = binding.split_whitespace().collect::<Vec<&str>>();
        assert!(words.len() < 24); // Test makes no sense if we have 24 words
        words.insert(words.len() / 2, "aaaaaa");

        let mnemonics = mf.add_from_words(&words);
        assert_eq!(mnemonics, 0);
    }

    #[test]
    fn test_mnem_fetch_add_from_words_bulk() {
        let mut mf = MnemFetcher::new(bip39::Language::English);

        let _mnemonics = mf.add_from_words(bip39::Language::English.word_list());
        assert_eq!(mf.gen_mnemonics.len(), 137);
    }
}

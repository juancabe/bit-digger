use std::{collections::HashSet, str::FromStr};

use bip39::Mnemonic;

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
    pub gen_mnemonics: Vec<Mnemonic>,
    wordlist: HashSet<&'a str>,
    word_ns: Vec<usize>,
}

impl<'a> MnemFetcher<'a> {
    pub fn new(lang: bip39::Language) -> Self {
        MnemFetcher {
            gen_mnemonics: Vec::new(),
            wordlist: lang.word_list().into_iter().map(|w| *w).collect(),
            word_ns: vec![MIN_WORDS, MAX_WORDS],
        }
    }

    /// Just add one already created mnemonic
    pub fn add_one(&mut self, mnemonic: Mnemonic) {
        self.gen_mnemonics.push(mnemonic);
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
    /// assert_eq!(mnemonics.len(), 0);
    /// ```
    pub fn add_from_words(&mut self, words: &[&str]) -> &[Mnemonic] {
        // let words = words.into_iter().filter(|w| self.wordlist.contains(w));

        let valid_words = words
            .iter()
            .filter(|w| self.wordlist.contains(**w))
            .map(|w| *w)
            .collect::<Vec<&str>>();

        let mut valid_words_str = String::new(); // String that contains all the valid words
        let mut valid_words_ptr: Vec<usize> = vec![0; valid_words.len()]; // Pointer to the start of each (word )
        //                                                                                                (^    )

        // Construct the words String along with the pointers
        for (i, w) in valid_words.iter().enumerate() {
            valid_words_ptr[i] = valid_words_str.len();
            valid_words_str.push_str(w);
            valid_words_str.push_str(" ");
        }
        assert_eq!(valid_words.len(), valid_words_ptr.len());

        let mut valid_mnemonics = vec![];

        for wc in self.word_ns.iter() {
            if *wc > valid_words_ptr.len() {
                continue;
            }
            for start_at in 0..valid_words_ptr.len() - (wc - 1) {
                MnemFetcher::window_check(
                    &valid_words_str,
                    &valid_words_ptr,
                    start_at,
                    *wc,
                    &mut valid_mnemonics,
                );
            }
        }

        // Only keep unique mnemonics
        valid_mnemonics.sort();
        valid_mnemonics.dedup();

        let vml = valid_mnemonics.len();

        self.gen_mnemonics.extend(valid_mnemonics);

        &self.gen_mnemonics[self.gen_mnemonics.len() - vml..]
    }

    /// Internal function to check wether a &str slice contains a valid mnemonic of `wc` words
    fn window_check(
        valid_words: &str,
        valid_words_ptr: &[usize],
        start_at: usize,
        wc: usize,
        valid_mnemonics: &mut Vec<Mnemonic>,
    ) {
        let start_index = valid_words_ptr[start_at];
        let end_index = valid_words_ptr[start_at + wc - 1]
            + valid_words[valid_words_ptr[start_at + wc - 1]..]
                .find(" ")
                .unwrap();

        let mnemonic = Mnemonic::from_str(&valid_words[start_index..end_index]);

        if mnemonic.is_ok() {
            valid_mnemonics.push(mnemonic.unwrap());
        }
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

        let mnemonics1 = mf.add_from_words(&words)[0].clone();

        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");

        let mnemonics2 = mf.add_from_words(&words)[0].clone();

        words.reverse();

        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");
        words.push("aaaa");

        words.reverse();

        let mnemonics3 = mf.add_from_words(&words)[0].clone();

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

        assert_eq!(mnemonics.len(), 0);

        let binding = VALID_MNEMONIC.to_string();
        let mut words = binding.split_whitespace().collect::<Vec<&str>>();
        assert!(words.len() < 24); // Test makes no sense if we have 24 words
        words.insert(words.len() / 2, "aaaaaa");

        let mnemonics = mf.add_from_words(&words);
        assert_eq!(mnemonics.len(), 0);
    }

    #[test]
    fn test_mnem_fetch_add_from_words_bulk() {
        let mut mf = MnemFetcher::new(bip39::Language::English);

        let _mnemonics = mf.add_from_words(bip39::Language::English.word_list());
        assert_eq!(mf.gen_mnemonics.len(), 137);
    }
}

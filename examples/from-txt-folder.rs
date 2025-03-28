use bit_digger::mnem_fetch::MnemFetcher;

fn get_mnems(directory: &str, max_amount: Option<usize>) -> MnemFetcher {
    println!("Searching for .txt files in {}", directory);
    // Search for all .txt files in the directory recursively
    let walker = walkdir::WalkDir::new(directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "txt"));

    let mut files: Vec<_> = walker.collect();

    println!("Found {} .txt files", files.len());

    if files.len() > max_amount.unwrap_or(files.len()) {
        println!(
            "Only processing the first {} files",
            max_amount.unwrap_or(files.len())
        );

        files.truncate(max_amount.unwrap_or(files.len()));
    }

    let mut mnem_fetcher = MnemFetcher::new(bip39::Language::English);

    for (index, file) in files.iter().enumerate() {
        let contents = std::fs::read_to_string(file.path()).expect("Failed to read file");
        let words: Vec<&str> = contents.split_whitespace().collect();

        let _ = mnem_fetcher.add_from_words(&words);

        if files.len() > 0 && (files.len() / 10 > 0) && index % (files.len() / 10) == 0 {
            println!("Processed {}% of the files", index * 100 / files.len());
        }
    }

    println!("Generated mnemonics: {}", mnem_fetcher.gen_mnemonics.len());

    mnem_fetcher
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprint!("Usage: {} <directory> [max_amount]", args[0]);
        std::process::exit(1);
    }

    let directory = &args[1];

    let max_amount = if args.len() == 3 {
        Some(args[2].parse::<usize>().expect("Invalid max_amount"))
    } else {
        None
    };

    let _mnem_fetcher = get_mnems(directory, max_amount);
}

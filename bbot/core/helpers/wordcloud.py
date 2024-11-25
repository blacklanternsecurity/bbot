import re
import csv
import string
import logging
import wordninja
from pathlib import Path
from contextlib import suppress
from collections import OrderedDict

from .misc import tldextract, extract_words

log = logging.getLogger("bbot.core.helpers.wordcloud")


class WordCloud(dict):
    """
    WordCloud is a specialized dictionary-like class for storing and aggregating
    words extracted from various data sources such as DNS names and URLs. The class
    is intended to facilitate the generation of target-specific wordlists and mutations.

    The WordCloud class can be accessed and manipulated like a standard Python dictionary.
    It also offers additional methods for generating mutations based on the words it contains.

    Attributes:
        parent_helper: The parent helper object that provides necessary utilities.
        devops_mutations: A set containing common devops-related mutations, loaded from a file.
        dns_mutator: An instance of the DNSMutator class for generating DNS-based mutations.

    Examples:
        >>> s = Scanner("www1.evilcorp.com", "www-test.evilcorp.com")
        >>> s.start_without_generator()
        >>> print(s.helpers.word_cloud)
        {
            "evilcorp": 2,
            "ec": 2,
            "www1": 1,
            "evil": 2,
            "www": 2,
            "w1": 1,
            "corp": 2,
            "1": 1,
            "wt": 1,
            "test": 1,
            "www-test": 1
        }

        >>> s.helpers.word_cloud.mutations(["word"], cloud=True, numbers=0, devops=False, letters=False)
        [
            [
                "1",
                "word"
            ],
            [
                "corp",
                "word"
            ],
            [
                "ec",
                "word"
            ],
            [
                "evil",
                "word"
            ],
            ...
        ]

        >>> s.helpers.word_cloud.dns_mutator.mutations("word")
        [
            "word",
            "word-test",
            "word1",
            "wordtest",
            "www-word",
            "wwwword"
        ]
    """

    def __init__(self, parent_helper, *args, **kwargs):
        self.parent_helper = parent_helper

        devops_filename = self.parent_helper.wordlist_dir / "devops_mutations.txt"
        self.devops_mutations = set(self.parent_helper.read_file(devops_filename))

        self.dns_mutator = DNSMutator()

        super().__init__(*args, **kwargs)

    def mutations(
        self, words, devops=True, cloud=True, letters=True, numbers=5, number_padding=2, substitute_numbers=True
    ):
        """
        Generate various mutations for the given list of words based on different criteria.

        Yields tuples of strings which can be joined on the desired delimiter, e.g. "-" or "_".

        Args:
            words (Union[str, Iterable[str]]): A single word or list of words to mutate.
            devops (bool): Whether to include devops-related mutations.
            cloud (bool): Whether to include mutations from the word cloud.
            letters (bool): Whether to include letter-based mutations.
            numbers (int): The maximum numeric mutations to include.
            number_padding (int): Padding for numeric mutations.
            substitute_numbers (bool): Whether to substitute numbers in mutations.

        Yields:
            tuple: A tuple containing each of the mutation segments.
        """
        if isinstance(words, str):
            words = (words,)
        results = set()
        for word in words:
            h = hash(word)
            if h not in results:
                results.add(h)
                yield (word,)
        if numbers > 0:
            if substitute_numbers:
                for word in words:
                    for number_mutation in self.get_number_mutations(word, n=numbers, padding=number_padding):
                        h = hash(number_mutation)
                        if h not in results:
                            results.add(h)
                            yield (number_mutation,)
        for word in words:
            for modifier in self.modifiers(
                devops=devops, cloud=cloud, letters=letters, numbers=numbers, number_padding=number_padding
            ):
                a = (word, modifier)
                b = (modifier, word)
                for _ in (a, b):
                    h = hash(_)
                    if h not in results:
                        results.add(h)
                        yield _

    def modifiers(self, devops=True, cloud=True, letters=True, numbers=5, number_padding=2):
        modifiers = set()
        if devops:
            modifiers.update(self.devops_mutations)
        if cloud:
            modifiers.update(set(self))
        if letters:
            modifiers.update(set(string.ascii_lowercase))
        if numbers > 0:
            modifiers.update(self.parent_helper.gen_numbers(numbers, number_padding))
        return modifiers

    def absorb_event(self, event):
        """
        Absorbs an event from a BBOT scan into the word cloud.

        This method updates the word cloud by extracting words from the given event. It aims to avoid including PTR
        (Pointer) records, as they tend to produce unhelpful mutations in the word cloud.

        Args:
            event (Event): The event object containing the words to be absorbed into the word cloud.
        """
        for word in event.words:
            self.add_word(word)
        if event.scope_distance == 0 and event.type.startswith("DNS_NAME"):
            subdomain = tldextract(event.data).subdomain
            if subdomain and not self.parent_helper.is_ptr(subdomain):
                for s in subdomain.split("."):
                    self.dns_mutator.add_word(s)

    def absorb_word(self, word, wordninja=True):
        """
        Absorbs a word into the word cloud after splitting it using a word extraction algorithm.

        This method splits the input word into smaller meaningful words using word extraction, and then adds each
        of them to the word cloud. The splitting is done using a predefined algorithm in the parent helper.

        Args:
            word (str): The word to be split and absorbed into the word cloud.
            wordninja (bool, optional): If True, word extraction is enabled. Defaults to True.

        Examples:
            >>> self.helpers.word_cloud.absorb_word("blacklantern")
            >>> print(self.helpers.word_cloud)
            {
                "blacklantern": 1,
                "black": 1,
                "bl": 1,
                "lantern": 1
            }
        """
        for w in self.parent_helper.extract_words(word, wordninja=wordninja):
            self.add_word(w)

    def add_word(self, word, lowercase=True):
        """
        Adds a word to the word cloud.

        This method updates the word cloud by adding a given word. If the word already exists in the cloud,
        its frequency count is incremented by 1. Optionally, the word can be converted to lowercase before adding.

        Args:
            word (str): The word to be added to the word cloud.
            lowercase (bool, optional): If True, the word will be converted to lowercase before adding. Defaults to True.

        Examples:
            >>> self.helpers.word_cloud.add_word("Example")
            >>> self.helpers.word_cloud.add_word("example")
            >>> print(self.helpers.word_cloud)
            {'example': 2}
        """
        if lowercase:
            word = word.lower()
        try:
            self[word] += 1
        except KeyError:
            self[word] = 1

    def get_number_mutations(self, base, n=5, padding=2):
        """
        Generates mutations of a base string by modifying the numerical parts or appending numbers.

        This method detects existing numbers in the base string and tries incrementing and decrementing them within a
        specified range. It also appends numbers at the end or after each word to generate more mutations.

        Args:
            base (str): The base string to generate mutations from.
            n (int, optional): The range of numbers to use for incrementing/decrementing. Defaults to 5.
            padding (int, optional): Zero-pad numbers up to this length. Defaults to 2.

        Returns:
            set: A set of mutated strings based on the base input.

        Examples:
            >>> self.helpers.word_cloud.get_number_mutations("www2-test", n=2)
            {
                "www0-test",
                "www1-test",
                "www2-test",
                "www2-test0",
                "www2-test00",
                "www2-test01",
                "www2-test1",
                "www3-test",
                "www4-test"
            }
        """
        results = set()

        # detects numbers and increments/decrements them
        # e.g. for "base2_p013", we would try:
        # - "base0_p013" through "base12_p013"
        # - "base2_p003" through "base2_p023"
        # limited to three iterations for sanity's sake
        for match in list(self.parent_helper.regexes.num_regex.finditer(base))[-3:]:
            span = match.span()
            before = base[: span[0]]
            after = base[span[-1] :]
            number = base[span[0] : span[-1]]
            numlen = len(number)
            maxnum = min(int("9" * numlen), int(number) + n)
            minnum = max(0, int(number) - n)
            for i in range(minnum, maxnum + 1):
                filled_num = str(i).zfill(numlen)
                results.add(f"{before}{filled_num}{after}")
                if not number.startswith("0"):
                    results.add(f"{before}{i}{after}")

        # appends numbers after each word
        # e.g., for "base_www", we would try:
        # - "base1_www", "base2_www", etc.
        # - "base_www1", "base_www2", etc.
        # limited to three iterations for sanity's sake
        number_suffixes = self.parent_helper.gen_numbers(n, padding)
        for match in list(self.parent_helper.regexes.word_regex.finditer(base))[-3:]:
            span = match.span()
            for suffix in number_suffixes:
                before = base[: span[-1]]
                after = base[span[-1] :]
                # skip if there's already a number
                if len(after) > 1 and not after[0].isdigit():
                    results.add(f"{before}{suffix}{after}")
        # basic cases so we don't miss anything
        for s in number_suffixes:
            results.add(f"{base}{s}")
            results.add(base)

        return results

    def truncate(self, limit):
        """
        Truncates the word cloud dictionary to retain only the top `limit` entries based on their occurrence frequencies.

        Args:
            limit (int): The maximum number of entries to retain in the word cloud.

        Examples:
            >>> self.helpers.word_cloud.update({"apple": 5, "banana": 2, "cherry": 8})
            >>> self.helpers.word_cloud.truncate(2)
            >>> self.helpers.word_cloud
            {'cherry': 8, 'apple': 5}
        """
        new_self = dict(self.json(limit=limit))
        self.clear()
        self.update(new_self)

    def json(self, limit=None):
        """
        Returns the word cloud as a sorted OrderedDict, optionally truncated to the top `limit` entries.

        Args:
            limit (int, optional): The maximum number of entries to include in the returned OrderedDict. If None, all entries are included.

        Returns:
            OrderedDict: A dictionary sorted by word frequencies, potentially truncated to the top `limit` entries.

        Examples:
            >>> self.helpers.word_cloud.update({"apple": 5, "banana": 2, "cherry": 8})
            >>> self.helpers.word_cloud.json(limit=2)
            OrderedDict([('cherry', 8), ('apple', 5)])
        """
        cloud_sorted = sorted(self.items(), key=lambda x: x[-1], reverse=True)
        if limit is not None:
            cloud_sorted = cloud_sorted[:limit]
        return OrderedDict(cloud_sorted)

    @property
    def default_filename(self):
        return self.parent_helper.preset.scan.home / "wordcloud.tsv"

    def save(self, filename=None, limit=None):
        """
        Saves the word cloud to a file. The cloud can optionally be truncated to the top `limit` entries.

        Args:
            filename (str, optional): The path to the file where the word cloud will be saved. If None, uses a default filename.
            limit (int, optional): The maximum number of entries to save to the file. If None, all entries are saved.

        Returns:
            tuple: A tuple containing a boolean indicating success or failure, and the resolved filename.

        Examples:
            >>> self.helpers.word_cloud.update({"apple": 5, "banana": 2, "cherry": 8})
            >>> self.helpers.word_cloud.save(filename="word_cloud.txt", limit=2)
            (True, Path('word_cloud.txt'))
        """
        if filename is None:
            filename = self.default_filename
        else:
            filename = Path(filename).resolve()
        try:
            if not self.parent_helper.mkdir(filename.parent):
                log.error(f"Failure creating or error writing to {filename.parent} when saving word cloud")
                return
            if len(self) > 0:
                log.debug(f"Saving word cloud to {filename}")
                with open(str(filename), mode="w", newline="") as f:
                    c = csv.writer(f, delimiter="\t")
                    for word, count in self.json(limit).items():
                        c.writerow([count, word])
                log.debug(f"Saved word cloud ({len(self):,} words) to {filename}")
                return True, filename
            else:
                log.debug("No words to save")
        except Exception as e:
            import traceback

            log.warning(f"Failed to save word cloud to {filename}: {e}")
            log.trace(traceback.format_exc())
        return False, filename

    def load(self, filename=None):
        """
        Loads a word cloud from a file. The file can be either a standard wordlist with one entry per line
        or a .tsv (tab-separated) file where the first row is the count and the second row is the associated entry.

        Args:
            filename (str, optional): The path to the file from which to load the word cloud. If None, uses a default filename.
        """
        if filename is None:
            wordcloud_path = self.default_filename
        else:
            wordcloud_path = Path(filename).resolve()
        log.verbose(f"Loading word cloud from {wordcloud_path}")
        try:
            with open(str(wordcloud_path), newline="") as f:
                c = csv.reader(f, delimiter="\t")
                for row in c:
                    if len(row) == 1:
                        self.add_word(row[0])
                    elif len(row) == 2:
                        with suppress(Exception):
                            count, word = row
                            count = int(count)
                            self[word] = count
            if len(self) > 0:
                log.success(f"Loaded word cloud ({len(self):,} words) from {wordcloud_path}")
        except Exception as e:
            import traceback

            log_fn = log.debug
            if filename is not None:
                log_fn = log.warning
            log_fn(f"Failed to load word cloud from {wordcloud_path}: {e}")
            if filename is not None:
                log.trace(traceback.format_exc())


class Mutator(dict):
    """
    Base class for generating mutations from a list of words.
    It accumulates words and produces mutations from them.
    """

    def mutations(self, words, max_mutations=None):
        mutations = self.top_mutations(max_mutations)
        ret = set()
        if isinstance(words, str):
            words = [words]
        for word in words:
            for m in self.mutate(word, mutations=mutations):
                ret.add("".join(m))
        return ret

    def mutate(self, word, max_mutations=None, mutations=None):
        if mutations is None:
            mutations = self.top_mutations(max_mutations)
        for mutation in mutations.keys():
            ret = []
            for s in mutation:
                if s is not None:
                    ret.append(s)
                else:
                    ret.append(word)
            yield ret

    def top_mutations(self, n=None):
        if n is not None:
            return dict(sorted(self.items(), key=lambda x: x[-1], reverse=True)[:n])
        else:
            return dict(self)

    def _add_mutation(self, mutation):
        if None not in mutation:
            return
        mutation = tuple([m for m in mutation if m != ""])
        try:
            self[mutation] += 1
        except KeyError:
            self[mutation] = 1

    def add_word(self, word):
        pass


class DNSMutator(Mutator):
    """
    DNS-specific mutator used by the `dnsbrute_mutations` module to generate target-specific subdomain mutations.

    This class extends the Mutator base class to add DNS-specific logic for generating
    subdomain mutations based on input words. It utilizes custom word extraction patterns
    and a wordninja model trained on DNS-specific data.

    Examples:
        >>> s = Scanner("www1.evilcorp.com", "www-test.evilcorp.com")
        >>> s.start_without_generator()
        >>> s.helpers.word_cloud.dns_mutator.mutations("word")
        [
            "word",
            "word-test",
            "word1",
            "wordtest",
            "www-word",
            "wwwword"
        ]
    """

    extract_word_regexes = [
        re.compile(r, re.I)
        for r in [
            r"[a-z]+",
            r"[a-z_-]+",
            r"[a-z0-9]+",
            r"[a-z0-9_-]+",
        ]
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wordlist_dir = Path(__file__).parent.parent.parent / "wordlists"
        wordninja_dns_wordlist = wordlist_dir / "wordninja_dns.txt.gz"
        self.model = wordninja.LanguageModel(wordninja_dns_wordlist)

    def mutations(self, words, max_mutations=None):
        if isinstance(words, str):
            words = [words]
        new_words = set()
        for word in words:
            for e in extract_words(word, acronyms=False, model=self.model, word_regexes=self.extract_word_regexes):
                new_words.add(e)
        return super().mutations(new_words, max_mutations=max_mutations)

    def add_word(self, word):
        spans = set()
        mutations = set()
        for r in self.extract_word_regexes:
            for match in r.finditer(word):
                span = match.span()
                if span not in spans:
                    spans.add(span)
        for start, end in spans:
            match_str = word[start:end]
            # skip digits
            if match_str.isdigit():
                continue
            before = word[:start]
            after = word[end:]
            basic_mutation = (before, None, after)
            mutations.add(basic_mutation)
            match_str_split = self.model.split(match_str)
            if len(match_str_split) > 1:
                for i, s in enumerate(match_str_split):
                    if s.isdigit():
                        continue
                    split_before = "".join(match_str_split[:i])
                    split_after = "".join(match_str_split[i + 1 :])
                    wordninja_mutation = (before + split_before, None, split_after + after)
                    mutations.add(wordninja_mutation)
        for m in mutations:
            self._add_mutation(m)

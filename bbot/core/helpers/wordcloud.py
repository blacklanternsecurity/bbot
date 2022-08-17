import csv
import string
import logging
from pathlib import Path
from contextlib import suppress
from collections import OrderedDict

log = logging.getLogger("bbot.core.helpers.wordcloud")


class WordCloud(dict):
    def __init__(self, parent_helper, *args, **kwargs):
        self.parent_helper = parent_helper
        self.max_backups = 20

        devops_filename = Path(__file__).parent.parent.parent / "wordlists" / "devops_mutations.txt"
        self.devops_mutations = set(self.parent_helper.read_file(devops_filename))

        super().__init__(*args, **kwargs)

    def mutations(
        self, words, devops=True, cloud=True, letters=True, numbers=5, number_padding=2, substitute_numbers=True
    ):
        if type(words) not in (set, list, tuple):
            words = (words,)
        results = set()
        for word in words:
            h = hash(word)
            if not h in results:
                results.add(h)
                yield (word,)
        if numbers > 0:
            if substitute_numbers:
                for word in words:
                    for number_mutation in self.get_number_mutations(word, n=numbers, padding=number_padding):
                        h = hash(number_mutation)
                        if not h in results:
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
        for word in event.words:
            self.add_word(word)

    def absorb_word(self, word, ninja=True):
        """
        Use word ninja to smartly split the word,
        e.g. "blacklantern" --> "black", "lantern"
        """
        for w in self.parent_helper.extract_words(word):
            self.add_word(w)

    def add_word(self, word, lowercase=True):
        if lowercase:
            word = word.lower()
        try:
            self[word] += 1
        except KeyError:
            self[word] = 1

    def get_number_mutations(self, base, n=5, padding=2):
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
            results.add(s)

        return results

    def truncate(self, limit):
        new_self = dict(self.json(limit=limit))
        self.clear()
        self.update(new_self)

    def json(self, limit=None):
        cloud_sorted = sorted(self.items(), key=lambda x: x[-1], reverse=True)
        if limit is not None:
            cloud_sorted = cloud_sorted[:limit]
        return OrderedDict(cloud_sorted)

    @property
    def default_filename(self):
        return self.parent_helper.scan.home / f"wordcloud.tsv"

    def save(self, filename=None, limit=None):
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
                log.debug(f"No words to save")
        except Exception as e:
            import traceback

            log.warning(f"Failed to save word cloud to {filename}: {e}")
            log.debug(traceback.format_exc())
        return False, filename

    def load(self, filename=None):
        if filename is None:
            wordcloud_path = self.default_filename
        else:
            wordcloud_path = Path(filename).resolve()
        log.verbose(f"Loading word cloud from {filename}")
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
                log.debug(traceback.format_exc())

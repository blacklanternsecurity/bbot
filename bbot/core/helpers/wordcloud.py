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
    def __init__(self, parent_helper, *args, **kwargs):
        self.parent_helper = parent_helper
        self.max_backups = 20

        devops_filename = self.parent_helper.wordlist_dir / "devops_mutations.txt"
        self.devops_mutations = set(self.parent_helper.read_file(devops_filename))

        self.dns_mutator = DNSMutator()

        super().__init__(*args, **kwargs)

    def mutations(
        self, words, devops=True, cloud=True, letters=True, numbers=5, number_padding=2, substitute_numbers=True
    ):
        if isinstance(words, str):
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
        if event.scope_distance == 0 and event.type.startswith("DNS_NAME"):
            subdomain = tldextract(event.data).subdomain
            if subdomain and not self.parent_helper.is_ptr(subdomain):
                for s in subdomain.split("."):
                    self.dns_mutator.add_word(s)

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
            log.trace(traceback.format_exc())
        return False, filename

    def load(self, filename=None):
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
        for mutation, count in mutations.items():
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

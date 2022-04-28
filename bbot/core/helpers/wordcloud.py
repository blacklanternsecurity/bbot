import string
import logging
from pathlib import Path

log = logging.getLogger("bbot.core.helpers.wordcloud")


class WordCloud(dict):
    def __init__(self, parent_helper, *args, **kwargs):
        self.parent_helper = parent_helper

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
            results.add((word,))
        if numbers > 0:
            if substitute_numbers:
                for word in words:
                    for number_mutation in self.get_number_mutations(word, n=numbers, padding=number_padding):
                        results.add((number_mutation,))
        for word in words:
            for modifier in self.modifiers(
                devops=devops, cloud=cloud, letters=letters, numbers=numbers, number_padding=number_padding
            ):
                results.add((word, modifier))
                results.add((modifier, word))
        return results

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

    def add_word(self, word):
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
        # basic case so we don't miss anything
        for s in number_suffixes:
            results.add(f"{base}{s}")

        return results

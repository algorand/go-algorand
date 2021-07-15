#!/usr/bin/env python3
from scripts import custom_search
import re
import pytest

class TestClass:
    regex_object = re.compile(r'\s+def test\_check\_file\_for\_missing\_search\_string\_with.*')

    def test_check_file_for_missing_search_string_with_results(self):
        # test line do not remove this comment
        assert custom_search.check_file_for_missing_search_string('tests/test_custom_search.py', self.regex_object, 'nonexistent string') == 2

    def test_check_file_for_missing_search_string_without_results(self):
        # test line do not remove this comment
        assert custom_search.check_file_for_missing_search_string('tests/test_custom_search.py', self.regex_object, 'do not remove this comment') == 0

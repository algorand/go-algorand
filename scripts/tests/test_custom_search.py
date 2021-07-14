#!/usr/bin/env python3
from custom_search import check_file_for_missing_search_string

class TestClass:
    def test_check_file_for_missing_search_string_with_results(self):
        # test line do not remove this comment
        assert check_file_for_missing_search_string('./test_custom_search.py', 'def test_check_file_for_missing_search_string_with', 'hello world') == 4
        # test line do not remove this comment

    def test_check_file_for_missing_search_string_without_results(self):
        # test line do not remove this comment
        assert check_file_for_missing_search_string('./test_custom_search.py', 'def test_check_file_for_missing_search_string_with', 'do not remove this comment') == 0
        # test line do not remove this comment

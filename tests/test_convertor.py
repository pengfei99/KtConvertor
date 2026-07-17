import os

import pytest

from ktconvertor.convertor import convert_kirbi
from minikerberos.common.ccache import CCACHE


@pytest.fixture
def ticket_src():
    return "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/tgt.kirbi"

@pytest.fixture
def empty_src():
    return "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/empty"

def test_convertor_with_given_path(ticket_src):

    ccache = "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/tgt.ccache"

    convert_kirbi(ticket_src, ccache)

def test_convertor_with_empty_src(empty_src):

    ccache = "C:/Users/pliu/Documents/git/KtConvertor/tests/tmp/tgt.ccache"

    convert_kirbi(empty_src, ccache)

def test_convertor_with_default_path(ticket_src):
    convert_kirbi(ticket_src)

def test_convertor_with_relative_path():
    kirbi = "./tests/tmp/tgt.kirbi"
    out_path = "./tests/tmp/tgt.ccache"
    convert_kirbi(kirbi,out_path)

def test_origin_code():
    kirbi = "./tests/tmp/tgt.kirbi"
    ccache = "./tests/tmp/tgt.ccache"
    abs_path = os.path.abspath(kirbi)
    print(abs_path)
    cc = CCACHE.from_kirbifile(abs_path)
    cc.to_file(ccache)

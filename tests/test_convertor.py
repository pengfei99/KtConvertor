from ktconvertor.convertor import convert_kirbi


def test_convertor_with_given_path():
    kirbi = "C:/Users/pliu/Documents/git/krbTicketConvertor/tests/tmp/tgt.kirbi"
    ccache = "C:/Users/pliu/Documents/git/krbTicketConvertor/tests/tmp/tgt.ccache"

    convert_kirbi(kirbi, ccache)

def test_convertor_with_default_path():
    kirbi = "C:/Users/pliu/Documents/git/krbTicketConvertor/tests/tmp/tgt.kirbi"
    convert_kirbi(kirbi)

def test_convertor_with_relative_path():
    kirbi = "./tests/tmp/tgt.kirbi"
    convert_kirbi(kirbi)

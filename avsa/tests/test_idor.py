"""Unit tests for the deterministic parsing/classification logic in
avsa.modules.idor. Pure helpers only — no live server required. The live
end-to-end run against DVAI is performed separately by the user.
"""

from avsa.modules.idor import (
    classify_idor,
    conversation_served,
    extract_own_ids,
)


# --- extract_own_ids --------------------------------------------------------

def test_extract_own_ids_from_sidebar():
    html = """
    <aside class="sidebar">
      <ul class="chatlist">
        <li><a href="/chat/1">Order question</a></li>
        <li><a href="/chat/5">Another chat</a></li>
      </ul>
    </aside>
    """
    assert extract_own_ids(html) == {1, 5}


def test_extract_own_ids_empty_when_no_chatlist():
    html = "<aside class='sidebar'><p class='muted'>No chats yet.</p></aside>"
    assert extract_own_ids(html) == set()


# --- conversation_served ----------------------------------------------------

def test_conversation_served_true_with_message_blocks():
    html = """
    <div class="conversation"><div class="messages">
      <div class="message user"><div class="content">hi</div></div>
      <div class="message assistant"><div class="content">hello</div></div>
    </div></div>
    """
    assert conversation_served(html) is True


def test_conversation_served_false_with_only_sidebar():
    # Sidebar present (ul.chatlist) but NO div.message in the conversation pane.
    html = """
    <aside class="sidebar"><ul class="chatlist">
      <li><a href="/chat/1">Order question</a></li>
    </ul></aside>
    <div class="conversation"><p class="muted empty">Start the conversation.</p></div>
    """
    assert conversation_served(html) is False


# --- classify_idor truth table ----------------------------------------------

def test_classify_hit_when_200_served_and_unowned():
    assert classify_idor(200, conversation_present=True, owned=False) is True


def test_classify_not_hit_when_owned():
    # Alice's own chat: served, but it's hers — not a violation.
    assert classify_idor(200, conversation_present=True, owned=True) is False


def test_classify_not_hit_on_404():
    assert classify_idor(404, conversation_present=False, owned=False) is False


def test_classify_not_hit_when_200_but_no_conversation():
    # 200 but nothing rendered in the conversation pane -> not a served chat.
    assert classify_idor(200, conversation_present=False, owned=False) is False

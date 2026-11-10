"""v0.4.2 event-driven waiting: GET /v1/wait stays open until something changes for its caller.

Four layers, each isolated from any production store: the wake signal itself, the events derived
from a ledger state, the HTTP behaviour of a waiting request, and a real service on a real store
driven by the real client.
"""
from copy import deepcopy
from http.client import HTTPConnection
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from pool import wakeups
from pool.httpd import Server
from pool.packages import ClientError
from verify import ROOT, call, command, server as running_service
from verify_delegation import ASSISTANT, OTHER, PERSON
from verify_support import scratch
from verify_upgrade import Client, PROJECT, capability, claim, control, register, seal
import verify_v030_review_read as review_fixture
import verify_v042_fixes as fixtures

SPEC = importlib.util.spec_from_file_location("wait_client", ROOT / "ops/round-client.py")
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)

COLLEAGUE = "other-person"
QUICK = 5  # seconds within which a woken request must have answered; a hold in these checks is 20


def get(port, path, token=None, timeout=30):
    connection = HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Authorization": "Bearer " + token} if token else {})
        response = connection.getresponse()
        return response.status, json.loads(response.read()), dict(response.getheaders())
    finally:
        connection.close()


class Background:
    """One call running beside the test, with the time it took."""

    def __init__(self, function, *args):
        self.value = self.error = self.seconds = None
        started = time.monotonic()

        def run():
            try:
                self.value = function(*args)
            except BaseException as error:
                self.error = error
            self.seconds = time.monotonic() - started
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def done(self):
        return not self.thread.is_alive()

    def result(self, timeout=30):
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise AssertionError("the call is still running")
        if self.error:
            raise self.error
        return self.value


def until(condition, timeout=10):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("the expected state was not reached")
        time.sleep(.01)


def event(name, kind="task-ready"):
    return {"type": kind, "key": (name * 64)[:64], "task_id": name}


class WakeSignals(unittest.TestCase):
    """The signal itself: what counts as a change, who is woken, and how many may wait."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="v042-wait-")
        self.addCleanup(self.temporary.cleanup)
        self.store = Path(self.temporary.name)
        self.reads = 0
        self.service = SimpleNamespace(desk=SimpleNamespace(store=self.store), snapshot=self.read)

    def read(self):
        self.reads += 1
        return {"state": {"read": self.reads}}

    def entry(self, number):
        (self.store / "ledger").mkdir(exist_ok=True)
        (self.store / "ledger" / f"{number:012d}.json").write_text("{}", encoding="utf-8")

    def test_marker_counts_published_entries_and_ignores_staging_files(self):
        self.assertIsNone(wakeups.ledger_marker(self.service), "no ledger folder yet")
        self.assertIsNone(wakeups.ledger_marker(SimpleNamespace()), "a service without a store")
        self.entry(1)
        (self.store / "ledger" / ".pending-0123456789abcdef").write_text("{", encoding="utf-8")
        self.assertEqual(wakeups.ledger_marker(self.service), 1)
        self.entry(2)
        self.assertEqual(wakeups.ledger_marker(self.service), 2)

    def test_only_a_grown_ledger_wakes_the_waiting_requests(self):
        signal = wakeups.Wakeups()
        self.entry(1)
        signal.ledger_changed(self.service)
        seen = signal.seen()
        for _ in range(3):
            signal.ledger_changed(self.service)  # a read-only or rejected request: nothing was appended
        self.assertEqual(signal.seen(), seen)
        self.entry(2)
        signal.ledger_changed(self.service)
        self.assertEqual(signal.seen(), seen + 1)

    def test_a_service_without_a_readable_ledger_folder_always_wakes(self):
        signal = wakeups.Wakeups()
        for expected in (1, 2, 3):
            signal.ledger_changed(SimpleNamespace())
            self.assertEqual(signal.seen(), expected)

    def test_one_ledger_read_serves_every_request_until_the_ledger_grows(self):
        signal = wakeups.Wakeups()
        self.entry(1)
        first = signal.snapshot(self.service)
        self.assertIs(signal.snapshot(self.service), first)
        self.assertIs(signal.snapshot(self.service), first)
        self.assertEqual(self.reads, 1)
        self.entry(2)
        self.assertIsNot(signal.snapshot(self.service), first)
        self.assertEqual(self.reads, 2)
        signal.snapshot(SimpleNamespace(snapshot=self.read))
        signal.snapshot(SimpleNamespace(snapshot=self.read))
        self.assertEqual(self.reads, 4, "without a marker nothing is reused")

    def test_wait_ends_on_a_notification_on_close_and_on_time(self):
        signal = wakeups.Wakeups()
        seen = signal.seen()
        started = time.monotonic()
        signal.wait(seen, .2)
        self.assertGreaterEqual(time.monotonic() - started, .19)
        sleeper = Background(signal.wait, seen, 30)
        time.sleep(.05)
        self.assertFalse(sleeper.done())
        signal.notify()
        sleeper.result(QUICK)
        self.assertLess(sleeper.seconds, QUICK)
        sleeper = Background(signal.wait, signal.seen(), 30)
        signal.close()
        sleeper.result(QUICK)
        started = time.monotonic()
        signal.wait(signal.seen(), 30)
        self.assertLess(time.monotonic() - started, 1, "a closed signal never sleeps")

    def test_a_notification_between_looking_and_sleeping_is_not_lost(self):
        signal = wakeups.Wakeups()
        seen = signal.seen()
        signal.notify()  # arrives after the caller looked at the state and before it sleeps
        started = time.monotonic()
        signal.wait(seen, 30)
        self.assertLess(time.monotonic() - started, 1)

    def test_waiting_places_are_limited_in_total_and_per_identity_and_given_back(self):
        signal = wakeups.Wakeups(waiters=3, per_identity=2)
        with signal.parked("a"), signal.parked("a"):
            with self.assertRaises(ClientError) as refused:
                with signal.parked("a"):
                    self.fail("a third place for one identity")
            self.assertEqual(refused.exception.status, 429)
            with signal.parked("b"):
                with self.assertRaises(ClientError) as refused:
                    with signal.parked("c"):
                        self.fail("a fourth place in total")
                self.assertEqual(refused.exception.status, 429)
        self.assertEqual(signal.waiting, {})
        with self.assertRaises(RuntimeError):
            with signal.parked("a"):
                raise RuntimeError("the request failed while waiting")
        self.assertEqual(signal.waiting, {})


class EventsFromState(unittest.TestCase):
    """What a state holds for one identity, and how an event's key follows its subject."""

    def setUp(self):
        self.service, self.state, self.task, self.claim, _ = review_fixture.fixture_service()
        self.state["pilot"]["grant:project-one:" + ASSISTANT] = {"roles": ["executor"], "resources": [], "version": 1}
        self.eligible = set()
        self.service.qualification = lambda state, task, actor: {"eligible": (task["task_id"], actor) in self.eligible}

    def events(self, actor=ASSISTANT):
        return wakeups.events(self.service, self.state, actor)

    def kinds(self, actor=ASSISTANT):
        return [row["type"] for row in self.events(actor)]

    def open_task(self, task_id="T09", **changes):
        task = {"task_id": task_id, "contract": {"project_id": "project-one", "open": True, "requirements": []},
                "status": "available", "version": 2, "scope_version": 1, "receiver": PERSON, "claims": [], **changes}
        self.state["tasks"][task_id] = task
        self.eligible.add((task_id, ASSISTANT))
        return task

    def working(self):
        """The holder is at work again: the returned delivery of the fixture is gone."""
        self.claim["deliveries"] = {}
        self.claim["W"]["state"] = "draft"
        self.assertEqual(self.events(), [])

    def only(self, kind, actor=ASSISTANT):
        rows = [row for row in self.events(actor) if row["type"] == kind]
        self.assertEqual(len(rows), 1, rows)
        return rows[0]

    def test_a_returned_delivery_is_reported_to_its_holder_only(self):
        row = self.only("review-returned")
        self.assertEqual((row["task_id"], row["claim_id"], row["revision"]), ("T01", "claim-one", "revision-2"))
        self.assertEqual(self.events(OTHER), [])
        self.assertEqual(self.kinds(PERSON), [])

    def test_a_task_the_identity_may_claim_is_reported_and_its_key_follows_the_task_version(self):
        self.assertNotIn("task-ready", self.kinds())
        task = self.open_task()
        row = self.only("task-ready")
        self.assertEqual((row["task_id"], row["version"], row["scope_version"]), ("T09", 2, 1))
        self.assertNotIn("task-ready", self.kinds(OTHER), "not eligible")
        task["version"] = 3
        self.assertNotEqual(self.only("task-ready")["key"], row["key"])
        task["status"] = "running"
        self.assertNotIn("task-ready", self.kinds())

    def test_a_delivery_waiting_for_review_is_reported_to_the_receiver(self):
        self.claim["W"].update(state="review", revision="revision-3")
        row = self.only("review-requested", PERSON)
        self.assertEqual((row["task_id"], row["claim_id"], row["revision"]), ("T01", "claim-one", "revision-3"))
        self.assertNotIn("review-requested", self.kinds(ASSISTANT))
        self.claim["W"]["revision"] = "revision-4"
        self.assertNotEqual(self.only("review-requested", PERSON)["key"], row["key"])
        self.service.visible = lambda *args: False
        self.assertEqual(self.kinds(PERSON), [])

    def test_scope_change_interruption_and_cancel_request_are_reported_to_the_holder(self):
        self.working()
        self.claim["scope_ack_pending"] = True
        first = self.only("scope-changed")
        self.assertEqual(first["scope_version"], 1)
        self.claim["W"]["scope"] = 2
        self.assertNotEqual(self.only("scope-changed")["key"], first["key"])
        self.claim["recovery"] = {"status": "pending", "by": "system-admin", "event": "interruption-1", "reason": "host restarted"}
        self.assertEqual(self.only("interrupted")["reason"], "host restarted")
        self.task["cancel_requested"] = True
        self.assertEqual(self.kinds(), ["cancel-requested", "interrupted", "scope-changed"])
        self.assertEqual(self.events(OTHER), [])
        self.claim["recovery"]["by"] = ASSISTANT
        self.assertNotIn("interrupted", self.kinds(), "the holder's own stop is not news to the holder")
        self.claim["L"] = "released"
        self.assertEqual(self.events(), [])

    def test_a_granted_resource_is_reported_to_the_window_that_asked(self):
        self.working()
        self.state["security"] = {"schema": 5, "phase": "ready", "execution": {"actions": {
            "act-one": {"id": "act-one", "executor_id": ASSISTANT, "state": "granted", "grant_id": "grant-one", "generation": 1,
                        "task_id": "T01", "claim_id": "claim-one"},
            "act-two": {"id": "act-two", "executor_id": ASSISTANT, "state": "queued", "task_id": "T01", "claim_id": "claim-one"},
            "act-far": {"id": "act-far", "executor_id": OTHER, "state": "granted", "grant_id": "grant-far", "generation": 1}}}}
        row = self.only("resource-granted")
        self.assertEqual((row["action_id"], row["grant_id"], row["task_id"]), ("act-one", "grant-one", "T01"))
        self.assertEqual(self.only("resource-granted", OTHER)["action_id"], "act-far")
        self.state["security"]["schema"] = 4
        self.assertEqual(self.events(), [])

    def test_reading_events_leaves_the_state_untouched_and_gives_the_same_answer_again(self):
        self.open_task()
        self.claim["scope_ack_pending"] = True
        before = deepcopy(self.state)
        first = self.events()
        self.assertEqual(self.state, before)
        self.assertEqual(self.events(), first)
        self.assertEqual(wakeups.cursor_of(first), wakeups.cursor_of(list(reversed(first))))
        self.assertTrue(wakeups.CURSOR.fullmatch(wakeups.cursor_of(first)))
        self.assertTrue(all(wakeups.CURSOR.fullmatch(row["key"]) for row in first))
        self.assertEqual(len({row["key"] for row in first}), len(first))
        self.open_task("T10")
        self.assertNotEqual(wakeups.cursor_of(self.events()), wakeups.cursor_of(first))

    def test_one_answer_carries_a_bounded_number_of_events(self):
        for number in range(wakeups.EVENT_LIMIT + 10):
            self.open_task(f"T{number + 100}")
        self.assertEqual(len(self.events()), wakeups.EVENT_LIMIT)


class WaitingRequests(fixtures.ServiceFixture):
    """A real HTTP server over the fixture service; the events are set by the test."""

    def setUp(self):
        super().setUp()
        self.pending = {}
        reader = patch("pool.wakeups.events", side_effect=lambda service, state, actor: list(self.pending.get(actor, [])))
        reader.start()
        self.addCleanup(reader.stop)
        self.tokens = {PERSON: "p" * 43, COLLEAGUE: "o" * 43}  # two people on their first, service-issued credential
        for name in self.tokens:
            self.state["pilot"]["identity:" + name]["credential"] = 1
        with patch("build.client_bundle_bytes", return_value=b"fixture"):
            self.server = Server(0, self.service, self.tokens)
        self.port = self.server.server_address[1]
        self.signal = self.server.wakeups
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.token = self.fixture.old  # the assistant window's own credential

    def stop(self):
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(10)
        self.server.server_close()

    def wait(self, cursor="", hold=0, token=None):
        query = "&".join(part for part in ("cursor=" + cursor if cursor else "", f"timeout={hold}") if part)
        return get(self.port, "/v1/wait?" + query, token or self.token)

    def park(self, actor=ASSISTANT, hold=20):
        token = self.token if actor == ASSISTANT else self.tokens[actor]
        before = sum(self.signal.waiting.values())
        cursor = wakeups.cursor_of(self.pending.get(actor, []))
        parked = Background(self.wait, cursor, hold, token)
        until(lambda: sum(self.signal.waiting.values()) == before + 1 or parked.done())
        return parked

    def post(self, token=None):
        """Any write request; here one the service refuses."""
        connection = HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            body = json.dumps({"request_id": "v042-wait-post"}).encode()
            connection.request("POST", "/v1/claim", body, {"Authorization": "Bearer " + (token or self.token),
                                                           "Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def ledger_entry(self, number):
        folder = self.fixture.root / "ledger"
        folder.mkdir(exist_ok=True)
        (folder / f"{number:012d}.json").write_text("{}", encoding="utf-8")

    def test_the_service_states_that_it_can_be_waited_on(self):
        status, value, _ = get(self.port, "/v1/features", self.token)
        self.assertEqual(status, 200)
        self.assertIs(value["features"]["wait"], True)
        self.assertEqual(value["wait"], {"max_seconds": wakeups.MAX_HOLD})

    def test_an_unknown_cursor_is_answered_at_once_and_the_current_one_is_held(self):
        self.pending[ASSISTANT] = [event("a"), event("b", "review-returned")]
        started = time.monotonic()
        status, value, _ = self.wait(hold=20)
        self.assertLess(time.monotonic() - started, QUICK)
        self.assertEqual(status, 200)
        self.assertEqual(value, {"cursor": wakeups.cursor_of(self.pending[ASSISTANT]), "changed": True,
                                 "events": self.pending[ASSISTANT]})
        self.assertEqual(self.signal.waiting, {}, "an immediate answer takes no waiting place")
        started = time.monotonic()
        status, again, _ = self.wait(value["cursor"], 1)
        self.assertGreaterEqual(time.monotonic() - started, .9)
        self.assertEqual((status, again), (200, {**value, "changed": False}))
        status, empty, _ = self.wait(token=self.tokens[PERSON])
        self.assertEqual((status, empty["events"], empty["changed"]), (200, [], True))

    def test_a_write_wakes_the_request_and_only_its_own_events_answer_it(self):
        mine, other = self.park(), self.park(PERSON)
        self.pending[ASSISTANT] = [event("a")]
        self.assertIn(self.post(), (400, 403, 409))
        status, value, _ = mine.result(QUICK)
        self.assertLess(mine.seconds, QUICK)
        self.assertEqual((status, value["changed"], value["events"]), (200, True, [event("a")]))
        time.sleep(.2)
        self.assertFalse(other.done(), "nothing changed for the other identity")
        self.pending[PERSON] = [event("c", "review-requested")]
        self.post()
        self.assertEqual(other.result(QUICK)[1]["events"], [event("c", "review-requested")])
        self.assertEqual(self.signal.waiting, {})

    def test_a_request_that_appends_nothing_wakes_nobody(self):
        self.ledger_entry(1)
        self.post()  # the signal now knows the ledger
        parked = self.park()
        seen = self.signal.seen()
        self.pending[ASSISTANT] = [event("a")]
        self.post()
        time.sleep(.2)
        self.assertEqual(self.signal.seen(), seen)
        self.assertFalse(parked.done())
        self.ledger_entry(2)
        self.post()
        self.assertEqual(parked.result(QUICK)[1]["events"], [event("a")])

    def test_requests_woken_together_share_one_ledger_read(self):
        self.signal.per_identity = 8
        self.ledger_entry(1)
        reads, original = [], self.service.desk.read
        self.service.desk.read = lambda: reads.append(1) or original()
        parked = [self.park() for _ in range(6)]
        self.assertEqual(len(reads), 1)
        self.pending[ASSISTANT] = [event("a")]
        self.ledger_entry(2)
        self.signal.ledger_changed(self.service)
        for request in parked:
            self.assertEqual(request.result(QUICK)[1]["events"], [event("a")])
        self.assertEqual(len(reads), 2)

    def test_waiting_requests_leave_at_once_when_the_service_freezes(self):
        parked = [self.park(), self.park(PERSON)]
        started = time.monotonic()
        self.assertEqual(self.service.lifecycle.freeze(10)["phase"], "frozen")
        self.assertLess(time.monotonic() - started, QUICK, "waiting requests must not delay an upgrade or a backup")
        for request in parked:
            status, value, headers = request.result(QUICK)
            self.assertEqual((status, value["status"], value["retryable"]), (503, "maintenance", True))
            self.assertEqual(headers["Retry-After"], "3")
        self.assertEqual(self.wait(hold=5)[0], 503)
        self.service.lifecycle.cancel()
        self.assertEqual(self.wait()[0], 200)
        self.assertEqual(self.signal.waiting, {})

    def test_a_maintenance_window_is_reported_instead_of_waiting(self):
        self.state["pilot"]["format"]["maintenance"] = True
        status, value, _ = self.wait(hold=20)
        self.assertEqual((status, value["status"]), (503, "rejected"))

    def test_waiting_requests_do_not_occupy_the_slots_of_working_requests(self):
        self.server.request_slots = threading.Semaphore(2)  # unbounded, so a slot given back twice would show
        self.signal.per_identity = 8
        parked = [self.park() for _ in range(5)]
        self.assertTrue(all(not request.done() for request in parked))
        for _ in range(3):
            self.assertEqual(get(self.port, "/v1/features", self.token)[0], 200)
        self.pending[ASSISTANT] = [event("a")]
        self.signal.notify()
        for request in parked:
            self.assertEqual(request.result(QUICK)[0], 200)
        until(lambda: self.server.request_slots.acquire(blocking=False))
        self.assertTrue(self.server.request_slots.acquire(blocking=False))
        self.assertFalse(self.server.request_slots.acquire(blocking=False), "every slot was given back exactly once")
        self.server.request_slots.release()
        self.server.request_slots.release()

    def test_waiting_places_are_limited_and_a_full_house_answers_429(self):
        self.signal.limit = 3
        parked = [self.park(), self.park()]
        status, value, _ = self.wait(wakeups.cursor_of([]), 20)
        self.assertEqual((status, value["status"]), (429, "rejected"))
        parked.append(self.park(PERSON))
        self.assertEqual(self.wait(wakeups.cursor_of([]), 20, self.tokens[COLLEAGUE])[0], 429)
        self.assertEqual(self.wait(token=self.tokens[COLLEAGUE])[0], 200, "asking without waiting is always possible")
        self.signal.notify()
        time.sleep(.2)
        self.assertTrue(all(not request.done() for request in parked), "a wake without a change keeps them waiting")
        self.pending.update({ASSISTANT: [event("a")], PERSON: [event("b")]})
        self.signal.notify()
        for request in parked:
            self.assertEqual(request.result(QUICK)[0], 200)
        self.assertEqual(self.signal.waiting, {})

    def test_a_waiting_request_ends_when_its_credential_stops_being_valid(self):
        parked = self.park(PERSON)
        self.tokens[PERSON] = "q" * 43
        self.signal.notify()
        self.assertEqual(parked.result(QUICK)[0], 401)
        self.tokens[PERSON] = "p" * 43
        parked = self.park(PERSON)
        del self.tokens[PERSON]
        self.tokens[COLLEAGUE] = "p" * 43  # the same token now names someone else
        self.pending[COLLEAGUE] = [event("z")]
        self.signal.notify()
        status, value, _ = parked.result(QUICK)
        self.assertEqual(status, 401)
        self.assertNotIn("events", value)
        self.assertEqual(self.signal.waiting, {})

    def test_invalid_requests_are_refused_without_waiting(self):
        for query in ("cursor=zz", "cursor=" + "A" * 64, "timeout=51", "timeout=abc", "timeout=-1", "timeout=0005",
                      "timeout=5&other=1", "timeout=5&timeout=6"):
            self.assertEqual(get(self.port, "/v1/wait?" + query, self.token)[0], 400, query)
        self.assertEqual(get(self.port, "/v1/wait?timeout=20")[0], 401)
        self.assertEqual(get(self.port, "/v1/wait?timeout=20", "x" * 43)[0], 401)
        self.server.is_round = False
        self.assertEqual(self.wait()[0], 404)
        self.assertEqual(self.signal.waiting, {})

    def test_closing_the_server_releases_waiting_requests(self):
        parked = [self.park(), self.park(PERSON)]
        started = time.monotonic()
        self.stop()
        self.assertLess(time.monotonic() - started, QUICK)
        for request in parked:
            self.assertEqual(request.result(QUICK)[0], 503)
        self.assertNotIn(self.signal.notify, self.service.lifecycle.listeners)


class ScriptedService:
    """Stands in for the service connection of the client: answers `features` and a script of `wait` answers."""

    def __init__(self, *script, features=None):
        self.script, self.waits = list(script), []
        self.features = {"api_protocol": 1, "security_schema": 5, "features": {"wait": True},
                         "wait": {"max_seconds": 50}} if features is None else features

    def call(self, route, token=None, body=None, **options):
        if route == "features":
            return self.features
        name, _, query = route.partition("?")
        assert name == "wait" and body is None, route
        values = dict(part.split("=") for part in query.split("&"))
        self.waits.append({"token": token, "cursor": values.get("cursor", ""), "hold": int(values["timeout"]),
                           "timeout": options.get("timeout")})
        if not self.script:
            raise AssertionError("the script has no further answer")
        step = self.script.pop(0)
        if callable(step):
            step = step()
        if isinstance(step, BaseException):
            raise step
        return {"cursor": wakeups.cursor_of(step), "changed": True, "events": step}


class Clock:
    """The client's view of time: pauses are recorded instead of taken, and the test may set the hour."""

    def __init__(self):
        self.slept, self.now = [], None

    def sleep(self, seconds):
        self.slept.append(seconds)
        if self.now is not None:
            self.now += seconds

    def monotonic(self):
        return time.monotonic() if self.now is None else self.now

    def __getattr__(self, name):
        return getattr(time, name)


def refusal(status):
    return client.RequestError(status, {"status": "rejected", "message": "fixture refusal"})


class ClientWait(unittest.TestCase):
    """The client's wait command against a scripted service."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="v042-wait-client-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "window" / "credential"
        self.state = client.State(self.path)
        self.write(token="t" * 43, url="http://127.0.0.1:1")
        self.clock = Clock()
        quiet = patch.object(client, "time", self.clock)
        quiet.start()
        self.addCleanup(quiet.stop)

    def write(self, **changes):
        with self.state.exclusive():
            self.state.data.update(changes)
            self.state.save()

    def stored(self):
        return json.loads(client.private_bytes(self.path.read_bytes(), decrypt=True))

    def run_wait(self, api, timeout=0):
        with patch.object(client, "endpoint", return_value=api):
            return client.wait_for_events(client.State(self.path), SimpleNamespace(timeout=timeout, allow_loopback=True))

    def test_pending_events_are_reported_once_and_remembered_in_the_credential_file(self):
        rows = [event("a"), event("b", "review-returned")]
        result = self.run_wait(ScriptedService(rows))
        self.assertEqual(result["status"], "changed")
        self.assertEqual(result["events"], [{"type": "task-ready", "task_id": "a"}, {"type": "review-returned", "task_id": "b"}])
        self.assertEqual((result["pending"], len(result["next"])), (2, 2))
        self.assertNotIn("key", json.dumps(result))
        self.assertEqual(self.stored()["wait_seen"], [row["key"] for row in rows])
        self.assertEqual(self.stored()["token"], "t" * 43)
        again = self.run_wait(ScriptedService(rows))
        self.assertEqual((again["status"], again["pending"]), ("idle", 2))

    def test_a_later_event_ends_the_wait_and_only_the_new_one_is_reported(self):
        self.write(wait_seen=[event("a")["key"]])
        api = ScriptedService([event("a")], [event("a")], [event("a"), event("c", "resource-granted")])
        result = self.run_wait(api, timeout=600)
        self.assertEqual(result["status"], "changed")
        self.assertEqual(result["events"], [{"type": "resource-granted", "task_id": "c"}])
        self.assertEqual(result["pending"], 2)
        self.assertEqual([step["cursor"] for step in api.waits], ["", wakeups.cursor_of([event("a")]), wakeups.cursor_of([event("a")])])
        self.assertEqual([step["hold"] for step in api.waits], [50, 50, 50])
        self.assertTrue(all(step["timeout"] > step["hold"] for step in api.waits), "the socket outlives the hold")
        self.assertTrue(all(step["token"] == "t" * 43 for step in api.waits))

    def test_an_event_that_only_went_away_does_not_end_the_wait(self):
        self.write(wait_seen=[event("a")["key"], event("b")["key"]])
        api = ScriptedService([event("a"), event("b")], [event("a")], [event("a"), event("b")])
        result = self.run_wait(api, timeout=600)
        self.assertEqual(len(api.waits), 3)
        self.assertEqual(result["events"], [{"type": "task-ready", "task_id": "b"}], "it came back, so it is news again")
        self.assertEqual(self.stored()["wait_seen"], [event("a")["key"], event("b")["key"]])

    def test_the_wait_ends_idle_when_its_time_is_over(self):
        self.clock.now = 0.0
        api = ScriptedService([], lambda: setattr(self.clock, "now", 40.0) or [], lambda: setattr(self.clock, "now", 70.0) or [])
        self.assertEqual(self.run_wait(api, timeout=70), {"status": "idle", "waited": 70, "pending": 0})
        self.assertEqual([step["hold"] for step in api.waits], [50, 50, 30])
        self.clock.now = 0.0
        api = ScriptedService([event("a")], lambda: setattr(self.clock, "now", 9.5) or [event("a")],
                              lambda: setattr(self.clock, "now", 10.4) or [event("a")])
        self.write(wait_seen=[event("a")["key"]])
        self.assertEqual(self.run_wait(api, timeout=10), {"status": "idle", "waited": 10, "pending": 1})
        self.assertEqual([step["hold"] for step in api.waits], [10, 10, 1], "half a second left: one more second, not an early end")

    def test_the_hold_follows_the_limit_the_service_states(self):
        api = ScriptedService([], [event("a")], features={"api_protocol": 1, "security_schema": 5, "features": {"wait": True},
                                                          "wait": {"max_seconds": 20}})
        self.run_wait(api, timeout=600)
        self.assertEqual([step["hold"] for step in api.waits], [20, 20])

    def test_a_service_without_the_interface_is_named_as_such(self):
        for features in ({"api_protocol": 1, "security_schema": 5, "features": {}},
                         {"api_protocol": 1, "security_schema": 5, "features": {"wait": True}},
                         {"api_protocol": 1, "security_schema": 5, "features": {"wait": True}, "wait": {"max_seconds": "50"}}):
            api = ScriptedService(features=features)
            with self.assertRaisesRegex(ValueError, "poll"):
                self.run_wait(api, timeout=600)
            self.assertEqual(api.waits, [])

    def test_a_service_that_is_briefly_away_is_asked_again(self):
        api = ScriptedService([], refusal(503), ConnectionResetError("fixture"), refusal(429), [event("a")])
        result = self.run_wait(api, timeout=600)
        self.assertEqual(result["status"], "changed")
        self.assertEqual(len(api.waits), 5)
        pauses = self.clock.slept
        self.assertEqual(len(pauses), 3)
        self.assertTrue(2 <= pauses[0] < pauses[1] < pauses[2] <= 31, pauses)

    def test_a_service_that_stays_away_ends_the_wait_idle_with_the_reason(self):
        self.clock.now = 0.0
        api = ScriptedService([], lambda: setattr(self.clock, "now", 9.0) or refusal(503), refusal(503))
        self.assertEqual(self.run_wait(ScriptedService(refusal(503)))["status"], "idle", "asked once, no time to wait")
        result = self.run_wait(api, timeout=10)
        self.assertEqual((result["status"], result["pending"]), ("idle", 0))
        self.assertIn("503", result["notice"])
        self.assertEqual(self.clock.slept, [1.0], "no pause longer than the time that is left")
        self.assertEqual([step["hold"] for step in api.waits], [10, 10, 0])

    def test_a_refusal_that_will_not_pass_is_reported(self):
        for status in (400, 403, 404):
            with self.assertRaises(client.RequestError) as raised:
                self.run_wait(ScriptedService([], refusal(status)), timeout=600)
            self.assertEqual(raised.exception.status, status)

    def test_a_token_activated_by_another_command_is_picked_up(self):
        def rotated():
            self.write(token="n" * 43)
            return refusal(401)
        api = ScriptedService([], rotated, [event("a")])
        self.assertEqual(self.run_wait(api, timeout=600)["status"], "changed")
        self.assertEqual([step["token"] for step in api.waits], ["t" * 43, "t" * 43, "n" * 43])
        with self.assertRaises(client.RequestError) as raised:
            self.run_wait(ScriptedService([], refusal(401)), timeout=600)
        self.assertEqual(raised.exception.status, 401)

    def test_the_credential_file_stays_free_for_other_commands_while_waiting(self):
        def other_command():
            with client.State(self.path).exclusive():  # fails if the waiting command still holds the file
                pass
            return [event("a")]
        self.assertEqual(self.run_wait(ScriptedService([], other_command), timeout=600)["status"], "changed")

    def test_an_answer_that_is_not_a_wait_result_is_refused(self):
        class Wrong(ScriptedService):
            def call(self, route, token=None, body=None, **options):
                return self.features if route == "features" else self.answer
        for answer in ({}, [], {"cursor": "x", "events": []}, {"cursor": "a" * 64, "events": [{"type": "task-ready"}]},
                       {"cursor": "a" * 64, "events": "none"}):
            api = Wrong()
            api.answer = answer
            with self.assertRaisesRegex(ValueError, "等待结果无效"):
                self.run_wait(api)

    def test_the_command_line_accepts_the_wait_command(self):
        args = client.build_parser().parse_args(["--state", str(self.path), "wait"])
        self.assertEqual((args.action, args.timeout), ("wait", 600))
        args = client.build_parser().parse_args(["--state", str(self.path), "wait", "--timeout", "30"])
        self.assertEqual(args.timeout, 30)
        for timeout in (-1, 86401):
            with self.assertRaises(ValueError):
                self.run_wait(ScriptedService([]), timeout=timeout)

    def test_the_run_loop_waits_for_a_change_and_falls_back_to_sleeping(self):
        self.state.data = {"token": "t" * 43}
        api = ScriptedService([event("a")])
        cursor = client.pause_until_change(self.state, api, wakeups.cursor_of([]))
        self.assertEqual(cursor, wakeups.cursor_of([event("a")]))
        self.assertEqual((api.waits[0]["hold"], api.waits[0]["cursor"]), (30, wakeups.cursor_of([])))
        self.assertLess(self.clock.slept[-1], 2, "a change is followed at once")
        for api in (ScriptedService(features={"api_protocol": 1, "security_schema": 3, "features": {}}),
                    ScriptedService(refusal(429)), ScriptedService(ConnectionResetError("fixture"))):
            self.assertEqual(client.pause_until_change(self.state, api, "kept"), "kept")
            self.assertTrue(24 <= self.clock.slept[-1] <= 36, "the earlier pause between two polls")


class RealService(unittest.TestCase):
    """The packaged service on a disposable real store, with real requests and the real client."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = scratch("v042-wait-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.project = project = Path(cls.scratch.name)
        with zipfile.ZipFile(ROOT / "dist" / "task-pool-local.zip") as package:
            package.extractall(project)
        initial = command(project, "init", "--worker", "worker-a", "--worker", "worker-b", "--receiver", "reviewer",
                          "--authority", "v0.4.2 wait fixture")
        cls.tokens = json.loads(Path(initial["credentials"]).read_bytes())["tokens"]
        cls.tokens["admin"] = command(project, "init-admin")["token"]
        brief = project / "brief.md"
        brief.write_text("synthetic input", encoding="utf-8")
        for number in (1, 2):
            command(project, "add-task", "--request-id", f"wait-legacy-{number}", "--title", f"Old {number}",
                    "--input", brief, "--criterion", "ready")
        command(project, "upgrade-migrate", "--upgrade", "fixture-v2", "--image", "1" * 64)
        command(project, "round-migrate", "--upgrade", "fixture-v3", "--image", "2" * 64)
        command(project, "maintenance", "off", "--request-id", "wait-fixture-open")
        cls.running = running_service(project)
        _, cls.url = cls.running.__enter__()
        cls.addClassCleanup(cls.running.__exit__, None, None, None)
        cls.admin, cls.worker, cls.receiver = (Client(cls.url, cls.tokens[name]) for name in ("admin", "worker-a", "reviewer"))
        for name, role in (("worker-a", "executor"), ("worker-b", "executor"), ("reviewer", "receiver")):
            cls.admin.post("identity-bind", request="wait-bind-" + name, name=name, kind="human", owner=name,
                           reason="isolated wait fixture", source=None)
            cls.admin.post("project-grant", request="wait-grant-" + name, project_id=PROJECT, name=name, roles=[role],
                           resources=[], version=0)
        capability(cls.worker, "worker-a")
        cls.sequence = 0

    def wait(self, name, cursor="", hold=0):
        status, value = call(self.url + "/wait?" + "&".join(
            part for part in ("cursor=" + cursor if cursor else "", f"timeout={hold}") if part), self.tokens[name])
        self.assertEqual(status, 200, value)
        return value

    def cursor(self, name):
        return self.wait(name)["cursor"]

    def publish(self):
        type(self).sequence += 1
        admin = Client(self.url, self.tokens["admin"])
        admin.sequence = 1000 * self.sequence
        task = register(admin, "reviewer", dispatch={"mode": "open", "subjects": [], "capabilities": [],
                                                     "automation": "notify", "owner": "admin"})
        control(admin, "task-publish", self.worker.get("tasks/" + task["task_id"])["task"])
        return self.worker.get("tasks/" + task["task_id"])["task"]

    def parked(self, name, hold=20):
        """A waiting request and the events its caller already knew."""
        known = self.wait(name)
        waiting = Background(self.wait, name, known["cursor"], hold)
        time.sleep(.5)  # let the request reach the service and start waiting
        self.assertFalse(waiting.done())
        waiting.known = {row["key"] for row in known["events"]}
        return waiting

    def news(self, waiting, kind):
        answer = waiting.result(QUICK + 5)
        self.assertLess(waiting.seconds, QUICK + 5, "the hold was 20 seconds; the answer must not wait for it")
        self.assertTrue(answer["changed"])
        return [row for row in answer["events"] if row["key"] not in waiting.known and row["type"] == kind]

    def test_1_a_published_task_reaches_a_waiting_worker_at_once(self):
        self.assertEqual(call(self.url + "/features", self.tokens["worker-a"])[1]["wait"], {"max_seconds": 50})
        quiet = self.wait("worker-a", self.cursor("worker-a"), 1)
        self.assertFalse(quiet["changed"])
        waiting, other = self.parked("worker-a"), self.parked("reviewer", 4)
        task = self.publish()
        self.assertEqual([(row["task_id"], row["version"], row["scope_version"]) for row in self.news(waiting, "task-ready")],
                         [(task["task_id"], task["version"], task["scope_version"])])
        answer = other.result()
        self.assertFalse(answer["changed"], "the receiver had nothing to act on: woken, but not answered early")
        self.assertGreaterEqual(other.seconds, 3.5)
        type(self).task = task

    def test_2_a_sealed_delivery_reaches_the_waiting_receiver_and_its_return_reaches_the_worker(self):
        receipt = claim(self.worker, self.task)
        self.assertNotIn(self.task["task_id"], [row.get("task_id") for row in self.wait("worker-a")["events"]],
                         "a claimed task is no longer offered")
        waiting = self.parked("reviewer")
        sealed = seal(self.worker, receipt)
        held = sealed["claim"]
        self.assertEqual([(row["task_id"], row["claim_id"]) for row in self.news(waiting, "review-requested")],
                         [(self.task["task_id"], held["claim_id"])])
        waiting = self.parked("worker-a")
        revision, record = next(reversed(held["deliveries"].items()))
        self.receiver.post("return", claim_id=held["claim_id"], revision=revision, manifest_sha256=record["manifest_sha256"],
                           criterion="ready", reason="isolated return for the wait check")
        self.assertEqual([(row["task_id"], row["claim_id"], row["revision"]) for row in self.news(waiting, "review-returned")],
                         [(self.task["task_id"], held["claim_id"], revision)])
        self.assertNotIn("review-requested", [row["type"] for row in self.wait("reviewer")["events"]])

    def test_3_the_client_command_returns_on_a_new_task_and_keeps_quiet_about_a_known_one(self):
        folder = self.project / "window"
        state = client.State(folder / "credential")
        with state.exclusive():
            state.data = {"token": self.tokens["worker-a"], "url": self.url.removesuffix("/v1")}
            state.save()
        args = SimpleNamespace(timeout=20, allow_loopback=True)
        first = client.wait_for_events(client.State(folder / "credential"), args)
        self.assertEqual(first["status"], "changed", "what is pending at the first call is reported once")
        self.assertIn("review-returned", [row["type"] for row in first["events"]])
        started = time.monotonic()
        idle = client.wait_for_events(client.State(folder / "credential"), SimpleNamespace(timeout=2, allow_loopback=True))
        self.assertEqual(idle["status"], "idle")
        self.assertEqual(idle["pending"], first["pending"])
        self.assertGreaterEqual(time.monotonic() - started, 1.5)
        waiting = Background(client.wait_for_events, client.State(folder / "credential"), args)
        time.sleep(1)
        self.assertFalse(waiting.done())
        with client.State(folder / "credential").exclusive():
            pass  # another command of the same window can open the credential meanwhile
        task = self.publish()
        result = waiting.result(QUICK + 5)
        self.assertEqual(result["status"], "changed")
        self.assertEqual([(row["type"], row["task_id"]) for row in result["events"]], [("task-ready", task["task_id"])])
        self.assertTrue(result["next"])

    def test_4_one_identity_holds_at_most_two_waiting_requests(self):
        waiting = [self.parked("worker-b"), self.parked("worker-b")]
        status, value = call(self.url + "/wait?cursor=" + self.cursor("worker-b") + "&timeout=20", self.tokens["worker-b"])
        self.assertEqual((status, value["status"]), (429, "rejected"))
        self.assertEqual(self.worker.get("identity")["identity"], "worker-a")
        type(self).idle = waiting

    @unittest.skipUnless(os.name == "posix", "the upgrade control socket runs inside Linux/WSL")
    def test_5_freezing_for_an_upgrade_is_not_delayed_by_waiting_requests(self):
        from pool.lifecycle import control_request
        store = self.project / ".state" / "local"
        started = time.monotonic()
        self.assertEqual(control_request(store, "freeze", 10)["phase"], "frozen")
        self.assertLess(time.monotonic() - started, QUICK)
        for request in self.idle:
            with self.assertRaises(AssertionError) as raised:  # wait() expects 200; the service answered 503
                request.result(QUICK)
            self.assertIn("maintenance", str(raised.exception))
        self.assertEqual(control_request(store, "cancel")["phase"], "running")
        self.assertEqual(self.wait("worker-b")["changed"], True)

    def test_6_answering_leaves_the_shared_ledger_snapshot_as_it_was_read(self):
        self.running.__exit__(None, None, None)  # the store has one writer; the check below opens it in this place
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", SNAPSHOT_CHECK, "worker-a", "worker-b", "reviewer", "admin"],
                                cwd=self.project, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        seen = json.loads(result.stdout)
        self.assertEqual(seen["reads"], 1, "every identity was answered from one ledger read")
        self.assertIn("review-returned", seen["events"]["worker-a"])
        self.assertIn("task-ready", seen["events"]["worker-a"])
        self.assertEqual(seen["events"]["worker-b"], [])


# Runs inside the unpacked package: the packaged service, its real store, no HTTP.
SNAPSHOT_CHECK = r"""
import json, sys
from copy import deepcopy
from pool import wakeups
from pool.service import Service, exclusive, state_path
store = state_path("local")
with exclusive(store):
    service = Service(store)
    try:
        reads, original = [], service.desk.read
        service.desk.read = lambda: reads.append(1) or original()
        signal, events = wakeups.Wakeups(), {}
        with service.lock:
            snapshot = signal.snapshot(service)
            before = deepcopy(snapshot)
            for name in sys.argv[1:]:
                with service.one_snapshot(signal.snapshot(service)):
                    assert service.credential_version(name) == 1, name
                    events[name] = [row["type"] for row in wakeups.events(service, service.snapshot()["state"], name)]
            assert snapshot == before, "answering a waiting request changed the snapshot other requests share"
        print(json.dumps({"reads": len(reads), "events": events}))
    finally:
        service.close()
"""


if __name__ == "__main__":
    unittest.main()


import json
import threading

import paho.mqtt.client as mqtt
from py_ecc.bls import G2ProofOfPossession as BLS
from aggregate_signature import aggregate, verify_aggregate

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensors/readings"
BATCH_SIZE = 10

batch = []
lock = threading.Lock()


def process_batch(items):
    messages = [item["message"] for item in items]
    signatures = [item["signature"] for item in items]
    public_keys = [item["public_key"] for item in items]
    proofs = [item["proof"] for item in items]

    # Check proof of possession before aggregating
    for item in items:
        if not BLS.KeyValidate(item["public_key"]):
            print("Rejected batch: invalid public key")
            return

        if not BLS.PopVerify(
            item["public_key"], item["proof"]
        ):
            print("Rejected batch: invalid proof of possession")
            return

    # Aggregate all signatures and verify the batch
    agg_signature = aggregate(signatures)

    valid = verify_aggregate(
        public_keys,
        messages,
        agg_signature,
        proofs,
    )

    print("\n--- Gateway batch result ---")
    print("Sensors received:", len(items))
    print("Aggregate signature size:", len(agg_signature), "bytes")
    print("Aggregate verification:", valid)

    for item in items:
        print(
            f"{item['sensor_id']}: "
            f"{item['message'].decode('utf-8')}"
        )

    if not valid:
        print("WARNING: Batch verification failed!")


def on_connect(client, userdata, flags, reason_code, properties):
    print("Gateway connected to MQTT:", reason_code)
    client.subscribe(TOPIC)
    print("Subscribed to:", TOPIC)


def on_message(client, userdata, msg):
    global batch

    try:
        payload = json.loads(msg.payload.decode("utf-8"))

        item = {
            "sensor_id": payload["sensor_id"],
            "message": bytes.fromhex(payload["message"]),
            "signature": bytes.fromhex(payload["signature"]),
            "public_key": bytes.fromhex(payload["public_key"]),
            "proof": bytes.fromhex(payload["proof"]),
        }

        with lock:
            batch.append(item)

            print(
                f"Received {item['sensor_id']} "
                f"({len(batch)}/{BATCH_SIZE})"
            )

            if len(batch) >= BATCH_SIZE:
                current_batch = batch[:BATCH_SIZE]
                batch = batch[BATCH_SIZE:]

                # Process the completed batch
                process_batch(current_batch)

    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("Rejected malformed MQTT message:", exc)


client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="iot-gateway",
)

client.on_connect = on_connect
client.on_message = on_message

print("Starting IoT Gateway...")
client.connect(BROKER, PORT, 60)
client.loop_forever()

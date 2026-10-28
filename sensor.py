
import json
import time

import paho.mqtt.client as mqtt

from aggregate_signature import keygen, sign

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensors/readings"
NUMBER_OF_SENSORS = 10


def main():
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="iot-sensor-publisher",
    )

    print("Connecting sensors to MQTT broker...")
    client.connect(BROKER, PORT, 60)
    client.loop_start()

    try:
        # Wait until the MQTT connection is established
        if not client.is_connected():
            time.sleep(1)

        for i in range(NUMBER_OF_SENSORS):
            sensor_id = f"sensor-{i + 1}"

            sk, pk, proof = keygen()

            # Deterministic example reading for demonstration
            reading = 20 + i
            message = (
                f"{sensor_id}:temperature={reading}"
            ).encode("utf-8")

            signature = sign(sk, message)

            payload = {
                "sensor_id": sensor_id,
                "message": message.hex(),
                "signature": signature.hex(),
                "public_key": pk.hex(),
                "proof": proof.hex(),
            }

            info = client.publish(
                TOPIC,
                json.dumps(payload),
                qos=1,
            )
            info.wait_for_publish()

            print(f"Published {sensor_id}: {reading} C")
            time.sleep(0.2)

    finally:
        client.disconnect()
        client.loop_stop()

    print("All sensors finished publishing.")


if __name__ == "__main__":
    main()


# & "C:\Program Files\mosquitto\mosquitto.exe" -v
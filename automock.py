from openai import OpenAI
client = OpenAI()

response = client.chat.completions.create(
  model="gpt-4",
  messages=[
    {
      "role": "system",
      "content": "You will be provided with a piece of C kernel code, and your task is to mock every referenced function and datatype being faithful to the kernel implementation. All structs, enums, macros should match the code. The resulting module should be possible to compile as a standalone. Only emit the final code that should compile with no warnings."
    },
    {
      "role": "user",
      "content": open("outbound_phy_packet_callback_function.c").read()
    }
  ]
)
print(response.choices[0].message.content)

async function testSse() {
  const res = await fetch(`http://localhost:8001/test`);
  
  console.log('Status:', res.status);
  
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  
  while (true) {
    const { done, value } = await reader.read();
    if (value) {
      console.log('Chunk:', JSON.stringify(decoder.decode(value, { stream: !done })));
    }
    if (done) {
      console.log('Done!');
      break;
    }
  }
}

testSse().catch(console.error);

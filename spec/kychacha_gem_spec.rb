RSpec.describe KychachaGem do
  it "generates a keypair" do
    keypair = KychachaGem.generate_keypair
    expect(keypair).not_to be_nil

  end
  it "keypair has pub and priv key" do
    keypair = KychachaGem.generate_keypair

    expect(keypair.private_key).not_to be_nil
    expect(keypair.public_key).not_to be_nil
  end
  it "round trip" do
    keypair = KychachaGem.generate_keypair
    message="Hey!! :3"

    encrypted_data=KychachaGem.encrypt(keypair.public_key,message)
    decrypted_msg=KychachaGem.decrypt(keypair.private_key,encrypted_data)

    expect(decrypted_msg.to_s).to eq(message)
  end
end

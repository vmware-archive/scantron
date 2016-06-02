require 'json'

vm_credentials = JSON.parse(File.read('vm_credentials.json'))

puts "hosts:"

vm_credentials.each do |credential|
  puts "- name: #{credential["name"]}"
  puts "  username: #{credential["identity"]}"
  puts "  password: #{credential["password"]}"
  puts "  addresses: []"
  puts
end

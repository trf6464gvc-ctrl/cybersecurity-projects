المشروع الرابع - فاحص قوة الباسورد
# Cybersecurity Project 4

password = input("دخل الباسورد: ")

if len(password) < 6:
    print("ضعيف جدا - محاولة اختراق سهلة!")
elif len(password) < 8:
    print("متوسط - ممكن يتفك")
else:
    if "@" in password or "#" in password or "$" in password:
        print("قوي جدا - آمن 🔐")
    else:
        print("قوي بس ضيف رمز زي @ أو #")
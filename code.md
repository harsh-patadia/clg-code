Below is an end‐to‐end sample solution for a full‐stack messaging application named “Pigeon.” This solution includes a Python–Django backend (with REST APIs, Channels for real‑time messaging, and MongoEngine for MongoDB integration) along with a React Native frontend that mimics Telegram’s look and feel using drawer, bottom tab, and stack navigators. (Keep in mind that in a real production app you’d likely add error handling, validations, and more advanced UI features—but the code below forms a solid starting point.)

---

## Backend (Python/Django)

### **Project Structure**

```plaintext
pigeon_backend/
├── core/
│   ├── __init__.py
│   ├── settings.py         # Django settings, Channels & MongoDB config
│   ├── urls.py             # Root URL routing
│   └── routing.py          # ASGI routing for WebSockets
├── manage.py               # Django command-line utility
├── requirements.txt        # Python dependencies list
├── users/
│   ├── __init__.py
│   ├── models.py           # MongoEngine User model
│   ├── serializers.py      # DRF serializers for users
│   ├── views.py            # API endpoints for registration/login
│   └── urls.py             # URL configuration for users
├── chats/
│   ├── __init__.py
│   ├── models.py           # MongoEngine Message model
│   ├── views.py            # API endpoints for sending/retrieving messages
│   ├── urls.py             # URL configuration for chats
│   ├── consumers.py        # Channels consumer for WebSocket messaging
│   └── routing.py          # WebSocket routing for chats
├── groups/
│   ├── __init__.py
│   ├── models.py           # MongoEngine Group model
│   ├── views.py            # API endpoints for group CRUD operations
│   └── urls.py             # URL configuration for groups
└── notifications/
    ├── __init__.py
    └── utils.py            # FCM integration for push notifications
```

### **1. requirements.txt**

```plaintext
Django>=3.2,<4.0
djangorestframework
channels
mongoengine
djangorestframework-simplejwt
pyfcm
```

### **2. manage.py**

```python
#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Make sure it's installed and available on your PYTHONPATH."
        ) from exc
    execute_from_command_line(sys.argv)
```

### **3. core/settings.py**

```python
import os
from pathlib import Path
import mongoengine
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'your-secret-key'
DEBUG = True
ALLOWED_HOSTS = []

INSTALLED_APPS = [
    'django.contrib.contenttypes',      # Required for content types (used by some packages)
    'django.contrib.auth',              # Needed by simplejwt (even if not used directly)
    'django.contrib.staticfiles',       # For static files
    'rest_framework',
    'channels',
    'users',
    'chats',
    'groups',
    'notifications',
]

MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
]

ROOT_URLCONF = 'core.urls'

ASGI_APPLICATION = 'core.routing.application'

# Connect to MongoDB using mongoengine
mongoengine.connect(
    db='pigeon_db',
    host='localhost',
    port=27017
)

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

# In-memory channel layer for development
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    },
}

STATIC_URL = '/static/'

# Simple JWT configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
}
```

### **4. core/urls.py**

```python
from django.urls import path, include

urlpatterns = [
    path('api/users/', include('users.urls')),
    path('api/chats/', include('chats.urls')),
    path('api/groups/', include('groups.urls')),
]
```

### **5. core/routing.py**

```python
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import chats.routing

application = ProtocolTypeRouter({
    "websocket": AuthMiddlewareStack(
        URLRouter(
            chats.routing.websocket_urlpatterns
        )
    ),
})
```

---

### **6. Users App**

#### **users/models.py**

```python
import datetime
import mongoengine as me

class Friend(me.EmbeddedDocument):
    friend_id = me.ObjectIdField(required=True)
    message_id = me.ObjectIdField(default=None)
    is_banned = me.BooleanField(default=False)

class User(me.Document):
    user_first_name = me.StringField(required=True)
    user_last_name = me.StringField(required=True)
    profile_photo = me.StringField(default=None)
    username = me.StringField(required=True, unique=True)
    email = me.EmailField(required=True, unique=True)
    password = me.StringField(required=True)  # Hashed password
    friends = me.EmbeddedDocumentListField(Friend)
    created_at = me.DateTimeField(default=datetime.datetime.utcnow)
    updated_at = me.DateTimeField(default=datetime.datetime.utcnow)
    
    meta = {
        'collection': 'users'
    }
```

#### **users/serializers.py**

```python
from rest_framework import serializers
from .models import User

class UserSerializer(serializers.Serializer):
    id = serializers.CharField(source="_id", read_only=True)
    user_first_name = serializers.CharField(required=True)
    user_last_name = serializers.CharField(required=True)
    profile_photo = serializers.CharField(allow_null=True, required=False)
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

class UserRegistrationSerializer(serializers.Serializer):
    user_first_name = serializers.CharField(required=True)
    user_last_name = serializers.CharField(required=True)
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
```

#### **users/views.py**

```python
import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import UserRegistrationSerializer, UserSerializer
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            if User.objects(email=data['email']).first():
                return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects(username=data['username']).first():
                return Response({"error": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
            
            hashed_password = make_password(data['password'])
            user = User(
                user_first_name=data['user_first_name'],
                user_last_name=data['user_last_name'],
                username=data['username'],
                email=data['email'],
                password=hashed_password
            )
            user.save()
            user_serializer = UserSerializer(user)
            return Response(user_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects(email=email).first()
        if user and check_password(password, user.password):
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
```

#### **users/urls.py**

```python
from django.urls import path
from .views import RegisterView, LoginView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
]
```

---

### **7. Chats App**

#### **chats/models.py**

```python
import datetime
import mongoengine as me

class Message(me.Document):
    sender_id = me.ObjectIdField(required=True)
    recipient_id = me.ObjectIdField(required=True)
    media_url = me.StringField(default=None)
    caption = me.StringField(default=None)
    content = me.StringField(required=True)
    timestamp = me.DateTimeField(default=datetime.datetime.utcnow)
    type = me.StringField(required=True, choices=['private', 'group'])
    
    meta = {
        'collection': 'messages'
    }
```

#### **chats/views.py**

```python
import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Message

class SendMessageView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ['sender_id', 'recipient_id', 'content', 'type']
        if not all(field in data for field in required_fields):
            return Response({"error": "Missing fields"}, status=status.HTTP_400_BAD_REQUEST)
        
        message = Message(
            sender_id=data['sender_id'],
            recipient_id=data['recipient_id'],
            content=data['content'],
            type=data['type'],
            media_url=data.get('media_url'),
            caption=data.get('caption'),
            timestamp=datetime.datetime.utcnow()
        )
        message.save()
        return Response({"message": "Message sent"}, status=status.HTTP_201_CREATED)

class MessageHistoryView(APIView):
    def get(self, request):
        sender_id = request.query_params.get('sender_id')
        recipient_id = request.query_params.get('recipient_id')
        if not sender_id or not recipient_id:
            return Response({"error": "sender_id and recipient_id are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        messages = Message.objects.filter(sender_id=sender_id, recipient_id=recipient_id).order_by('timestamp')
        messages_data = []
        for msg in messages:
            messages_data.append({
                'id': str(msg.id),
                'sender_id': str(msg.sender_id),
                'recipient_id': str(msg.recipient_id),
                'content': msg.content,
                'media_url': msg.media_url,
                'caption': msg.caption,
                'timestamp': msg.timestamp.isoformat(),
                'type': msg.type,
            })
        return Response(messages_data, status=status.HTTP_200_OK)
```

#### **chats/urls.py**

```python
from django.urls import path
from .views import SendMessageView, MessageHistoryView

urlpatterns = [
    path('send/', SendMessageView.as_view(), name='send_message'),
    path('history/', MessageHistoryView.as_view(), name='message_history'),
]
```

#### **chats/consumers.py**  
*(This consumer handles WebSocket connections for real‑time chat)*

```python
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from rest_framework_simplejwt.tokens import UntypedToken
from django.conf import settings
from jwt import decode as jwt_decode, InvalidTokenError

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Expect the JWT token in the query string, e.g., ?token=xxx
        query_string = self.scope['query_string'].decode()
        token = query_string.split('=')[1] if 'token=' in query_string else None
        if not token:
            await self.close()
            return
        try:
            payload = jwt_decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            self.user_id = payload.get('user_id')
            if not self.user_id:
                await self.close()
                return
            await self.accept()
        except InvalidTokenError:
            await self.close()

    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')
        if action == 'send_message':
            room = data.get('room')  # e.g., "user1_user2" or "group_123"
            message = data.get('message')
            await self.channel_layer.group_send(
                room,
                {
                    'type': 'chat_message',
                    'message': message,
                    'sender_id': self.user_id
                }
            )
        elif action == 'join':
            room = data.get('room')
            await self.channel_layer.group_add(room, self.channel_name)
        elif action == 'leave':
            room = data.get('room')
            await self.channel_layer.group_discard(room, self.channel_name)

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'sender_id': event['sender_id']
        }))

    async def disconnect(self, close_code):
        pass
```

#### **chats/routing.py**

```python
from django.urls import re_path
from .consumers import ChatConsumer

websocket_urlpatterns = [
    re_path(r'ws/chat/$', ChatConsumer.as_asgi()),
]
```

---

### **8. Groups App**

#### **groups/models.py**

```python
import datetime
import mongoengine as me

class GroupMember(me.EmbeddedDocument):
    user_id = me.ObjectIdField(required=True)
    joined_at = me.DateTimeField(default=datetime.datetime.utcnow)
    is_restricted = me.BooleanField(default=False)
    is_admin = me.BooleanField(default=False)
    is_banned = me.BooleanField(default=False)

class Group(me.Document):
    name = me.StringField(required=True)
    username = me.StringField(unique=True, sparse=True)
    profile_photo = me.StringField(default=None)
    description = me.StringField(default=None)
    is_public = me.BooleanField(default=False)
    members = me.EmbeddedDocumentListField(GroupMember)
    created_by = me.ObjectIdField(required=True)
    created_at = me.DateTimeField(default=datetime.datetime.utcnow)
    updated_at = me.DateTimeField(default=datetime.datetime.utcnow)
    
    meta = {
        'collection': 'groups'
    }
```

#### **groups/views.py**

```python
import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Group, GroupMember

class CreateGroupView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ['name', 'created_by']
        if not all(field in data for field in required_fields):
            return Response({"error": "Missing fields"}, status=status.HTTP_400_BAD_REQUEST)
        
        group = Group(
            name=data['name'],
            username=data.get('username'),
            profile_photo=data.get('profile_photo'),
            description=data.get('description'),
            is_public=data.get('is_public', False),
            created_by=data['created_by'],
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        # Add creator as admin member
        member = GroupMember(
            user_id=data['created_by'],
            is_admin=True
        )
        group.members.append(member)
        group.save()
        return Response({"message": "Group created", "group_id": str(group.id)}, status=status.HTTP_201_CREATED)

class JoinGroupView(APIView):
    def post(self, request):
        group_id = request.data.get('group_id')
        user_id = request.data.get('user_id')
        if not group_id or not user_id:
            return Response({"error": "Missing group_id or user_id"}, status=status.HTTP_400_BAD_REQUEST)
        
        group = Group.objects(id=group_id).first()
        if not group:
            return Response({"error": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if any(member.user_id == user_id for member in group.members):
            return Response({"error": "Already a member"}, status=status.HTTP_400_BAD_REQUEST)
        
        new_member = GroupMember(user_id=user_id)
        group.members.append(new_member)
        group.updated_at = datetime.datetime.utcnow()
        group.save()
        return Response({"message": "Joined group"}, status=status.HTTP_200_OK)
```

#### **groups/urls.py**

```python
from django.urls import path
from .views import CreateGroupView, JoinGroupView

urlpatterns = [
    path('create/', CreateGroupView.as_view(), name='create_group'),
    path('join/', JoinGroupView.as_view(), name='join_group'),
]
```

---

### **9. Notifications Utility**

#### **notifications/utils.py**

```python
from pyfcm import FCMNotification

API_KEY = 'your-fcm-api-key'
push_service = FCMNotification(api_key=API_KEY)

def send_push_notification(registration_id, message_title, message_body, data_message=None):
    result = push_service.notify_single_device(
        registration_id=registration_id,
        message_title=message_title,
        message_body=message_body,
        data_message=data_message
    )
    return result
```

---

## Frontend (React Native)

Below is a sample React Native project using React Navigation to simulate a Telegram-like UI. We use a combination of drawer, bottom tab, and stack navigators. The app includes screens for login/registration, private chats, and group CRUD and messaging. (For API calls, we use a simple API utility based on Axios.)

### **Project Structure**

```plaintext
PigeonApp/
├── App.js
├── package.json
├── navigation/
│   ├── DrawerNavigator.js
│   ├── BottomTabNavigator.js
│   └── StackNavigator.js
├── screens/
│   ├── LoginScreen.js
│   ├── RegisterScreen.js
│   ├── HomeScreen.js
│   ├── ChatScreen.js
│   ├── GroupListScreen.js
│   ├── GroupChatScreen.js
│   └── GroupCRUDScreen.js
├── components/
│   ├── MessageItem.js
│   └── ChatInput.js
└── utils/
    └── api.js
```

### **1. package.json**  
*(Make sure to install dependencies such as react-navigation, axios, and others.)*

```json
{
  "name": "PigeonApp",
  "version": "1.0.0",
  "main": "App.js",
  "dependencies": {
    "axios": "^0.27.2",
    "react": "18.0.0",
    "react-native": "0.69.0",
    "@react-navigation/native": "^6.0.13",
    "@react-navigation/drawer": "^6.4.1",
    "@react-navigation/bottom-tabs": "^6.4.1",
    "@react-navigation/stack": "^6.3.2",
    "react-native-gesture-handler": "^2.4.2",
    "react-native-reanimated": "^2.9.1",
    "react-native-safe-area-context": "^4.3.1",
    "react-native-screens": "^3.15.0"
  }
}
```

### **2. App.js**

```jsx
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import DrawerNavigator from './navigation/DrawerNavigator';

export default function App() {
  return (
    <NavigationContainer>
      <DrawerNavigator />
    </NavigationContainer>
  );
}
```

### **3. navigation/DrawerNavigator.js**

```jsx
import React from 'react';
import { createDrawerNavigator } from '@react-navigation/drawer';
import BottomTabNavigator from './BottomTabNavigator';
import GroupCRUDScreen from '../screens/GroupCRUDScreen';

const Drawer = createDrawerNavigator();

export default function DrawerNavigator() {
  return (
    <Drawer.Navigator initialRouteName="Home">
      <Drawer.Screen name="Home" component={BottomTabNavigator} />
      <Drawer.Screen name="Manage Groups" component={GroupCRUDScreen} />
    </Drawer.Navigator>
  );
}
```

### **4. navigation/BottomTabNavigator.js**

```jsx
import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import StackNavigator from './StackNavigator';
import GroupListScreen from '../screens/GroupListScreen';

const Tab = createBottomTabNavigator();

export default function BottomTabNavigator() {
  return (
    <Tab.Navigator>
      <Tab.Screen name="Chats" component={StackNavigator} />
      <Tab.Screen name="Groups" component={GroupListScreen} />
    </Tab.Navigator>
  );
}
```

### **5. navigation/StackNavigator.js**

```jsx
import React from 'react';
import { createStackNavigator } from '@react-navigation/stack';
import ChatScreen from '../screens/ChatScreen';
import LoginScreen from '../screens/LoginScreen';
import RegisterScreen from '../screens/RegisterScreen';
import HomeScreen from '../screens/HomeScreen';

const Stack = createStackNavigator();

export default function StackNavigator() {
  return (
    <Stack.Navigator initialRouteName="Login">
      {/* Authentication flow */}
      <Stack.Screen name="Login" component={LoginScreen} options={{headerShown: false}}/>
      <Stack.Screen name="Register" component={RegisterScreen} options={{headerShown: false}}/>
      
      {/* Once logged in */}
      <Stack.Screen name="Home" component={HomeScreen} options={{headerShown: false}}/>
      <Stack.Screen name="Chat" component={ChatScreen} options={{title: 'Chat'}}/>
    </Stack.Navigator>
  );
}
```

---

### **6. utils/api.js**

```jsx
import axios from 'axios';

const API_BASE_URL = 'http://your-backend-host:8000/api';

export const api = axios.create({
  baseURL: API_BASE_URL,
});

// Example: User registration
export const registerUser = async (userData) => {
  const response = await api.post('/users/register/', userData);
  return response.data;
};

// Example: User login
export const loginUser = async (credentials) => {
  const response = await api.post('/users/login/', credentials);
  return response.data;
};

// Example: Send message
export const sendMessage = async (messageData) => {
  const response = await api.post('/chats/send/', messageData);
  return response.data;
};

// Similarly, add functions for fetching message history, group CRUD, etc.
```

---

### **7. screens/LoginScreen.js**

```jsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
import { loginUser } from '../utils/api';

export default function LoginScreen({ navigation }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const onLogin = async () => {
    try {
      const data = await loginUser({ email, password });
      // Save token as needed (AsyncStorage) and navigate to Home
      navigation.replace('Home');
    } catch (error) {
      alert('Login failed');
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Pigeon Login</Text>
      <TextInput 
        placeholder="Email"
        value={email}
        onChangeText={setEmail}
        style={styles.input}
      />
      <TextInput 
        placeholder="Password"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        style={styles.input}
      />
      <Button title="Login" onPress={onLogin} />
      <Button title="Register" onPress={() => navigation.navigate('Register')} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex:1, justifyContent:'center', padding:20 },
  title: { fontSize:24, marginBottom:20, textAlign:'center' },
  input: { borderWidth:1, padding:10, marginBottom:10 }
});
```

---

### **8. screens/RegisterScreen.js**

```jsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
import { registerUser } from '../utils/api';

export default function RegisterScreen({ navigation }) {
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName]   = useState('');
  const [username, setUsername]   = useState('');
  const [email, setEmail]         = useState('');
  const [password, setPassword]   = useState('');

  const onRegister = async () => {
    try {
      const data = await registerUser({ 
        user_first_name: firstName,
        user_last_name: lastName,
        username,
        email,
        password
      });
      navigation.replace('Login');
    } catch (error) {
      alert('Registration failed');
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Pigeon Register</Text>
      <TextInput placeholder="First Name" value={firstName} onChangeText={setFirstName} style={styles.input} />
      <TextInput placeholder="Last Name" value={lastName} onChangeText={setLastName} style={styles.input} />
      <TextInput placeholder="Username" value={username} onChangeText={setUsername} style={styles.input} />
      <TextInput placeholder="Email" value={email} onChangeText={setEmail} style={styles.input} />
      <TextInput placeholder="Password" secureTextEntry value={password} onChangeText={setPassword} style={styles.input} />
      <Button title="Register" onPress={onRegister} />
      <Button title="Back to Login" onPress={() => navigation.goBack()} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex:1, justifyContent:'center', padding:20 },
  title: { fontSize:24, marginBottom:20, textAlign:'center' },
  input: { borderWidth:1, padding:10, marginBottom:10 }
});
```

---

### **9. screens/HomeScreen.js**

```jsx
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function HomeScreen({ navigation }) {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Welcome to Pigeon</Text>
      <Button title="Go to Chat" onPress={() => navigation.navigate('Chat', { recipientId: 'someUserId' })} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex:1, justifyContent:'center', alignItems:'center' },
  title: { fontSize:24, marginBottom:20 }
});
```

---

### **10. screens/ChatScreen.js**

```jsx
import React, { useState, useEffect } from 'react';
import { View, FlatList, StyleSheet } from 'react-native';
import MessageItem from '../components/MessageItem';
import ChatInput from '../components/ChatInput';
import { sendMessage } from '../utils/api';

export default function ChatScreen({ route }) {
  const { recipientId } = route.params;
  const [messages, setMessages] = useState([]);

  const handleSend = async (text) => {
    const messageData = {
      sender_id: 'loggedInUserId',  // Replace with actual user id from token/context
      recipient_id: recipientId,
      content: text,
      type: 'private'
    };
    try {
      await sendMessage(messageData);
      setMessages([...messages, { ...messageData, timestamp: new Date().toISOString() }]);
    } catch (error) {
      alert('Failed to send message');
    }
  };

  // For demonstration, messages could be fetched here via an API call

  return (
    <View style={styles.container}>
      <FlatList 
        data={messages}
        keyExtractor={(item, index) => index.toString()}
        renderItem={({item}) => <MessageItem message={item} />}
        style={styles.messagesList}
      />
      <ChatInput onSend={handleSend} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex:1 },
  messagesList: { flex:1, padding:10 }
});
```

---

### **11. screens/GroupListScreen.js**

```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, FlatList, TouchableOpacity, StyleSheet } from 'react-native';
// This screen lists available groups (fetched via API)
export default function GroupListScreen({ navigation }) {
  const [groups, setGroups] = useState([]);

  useEffect(() => {
    // Fetch groups via API and setGroups(...)
  }, []);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Groups</Text>
      <FlatList 
        data={groups}
        keyExtractor={(item) => item.id}
        renderItem={({item}) => (
          <TouchableOpacity onPress={() => navigation.navigate('Chat', { recipientId: item.id, type: 'group' })}>
            <Text style={styles.groupItem}>{item.name}</Text>
          </TouchableOpacity>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex:1, padding:20 },
  title: { fontSize:24, marginBottom:20 },
  groupItem: { padding:10, borderBottomWidth:1 }
});
```

---

### **12. screens/GroupCRUDScreen.js**

```jsx
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';
// This screen demonstrates simple group CRUD operations (create & join)
export default function GroupCRUDScreen({ navigation }) {
  const [groupName, setGroupName] = useState('');

  const createGroup = async () => {
    // Call API to create group with groupName
    alert('Group created!');
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Manage Groups</Text>
      <TextInput 
        placeholder="Enter group name"
        value={groupName}
        onChangeText={setGroupName}
        style={styles.input}
      />
      <Button title="Create Group" onPress={createGroup} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex:1, justifyContent:'center', padding:20 },
  title: { fontSize:24, marginBottom:20, textAlign:'center' },
  input: { borderWidth:1, padding:10, marginBottom:10 }
});
```

---

### **13. components/MessageItem.js**

```jsx
import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

export default function MessageItem({ message }) {
  return (
    <View style={styles.messageContainer}>
      <Text style={styles.messageText}>{message.content}</Text>
      <Text style={styles.timestamp}>{new Date(message.timestamp).toLocaleTimeString()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  messageContainer: { padding:10, marginVertical:5, backgroundColor:'#e1ffc7', borderRadius:8 },
  messageText: { fontSize:16 },
  timestamp: { fontSize:10, textAlign:'right', color:'#555' }
});
```

---

### **14. components/ChatInput.js**

```jsx
import React, { useState } from 'react';
import { View, TextInput, Button, StyleSheet } from 'react-native';

export default function ChatInput({ onSend }) {
  const [text, setText] = useState('');

  const handleSend = () => {
    if (text.trim() !== '') {
      onSend(text);
      setText('');
    }
  };

  return (
    <View style={styles.container}>
      <TextInput 
        style={styles.input}
        placeholder="Type your message..."
        value={text}
        onChangeText={setText}
      />
      <Button title="Send" onPress={handleSend} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flexDirection:'row', padding:10, borderTopWidth:1 },
  input: { flex:1, borderWidth:1, marginRight:10, padding:8, borderRadius:4 }
});
```

---

## Integration Summary

1. **Backend:**  
   – Run `pip install -r requirements.txt` in your virtual environment.  
   – Start MongoDB and then run `python manage.py runserver` to launch the backend.

2. **Frontend:**  
   – In your React Native project folder, run `npm install` (or `yarn install`).  
   – Ensure the API base URL in `utils/api.js` points to your backend host and port.  
   – Run your app (e.g., using Expo or React Native CLI).

This complete codebase demonstrates a full-stack messaging application with REST and real‑time features on the backend and a Telegram-like UI on the frontend. You can extend this foundation by adding more robust authentication state management, advanced error handling, and refined UI components as needed. Happy coding!
# Parameter Operation Functions by Category

## Float Operations (~60 functions)

### Arithmetic Operations
- CKFloatAbsoluteFloat - Absolute value of float
- CKFloatAddFloatFloat - Add two floats
- CKFloatAddFloatInt - Add float and int
- CKFloatDivideFloatFloat - Divide two floats
- CKFloatDivideFloatInt - Divide float by int
- CKFloatDivideIntFloat - Divide int by float
- CKFloatInverseFloat - Inverse (reciprocal) of float
- CKFloatInverseInt - Inverse (reciprocal) of int
- CKFloatMaxFloatFloat - Maximum of two floats
- CKFloatMaxFloatInt - Maximum of float and int
- CKFloatMinFloatFloat - Minimum of two floats
- CKFloatMinFloatInt - Minimum of float and int
- CKFloatMultiplyFloatFloat - Multiply two floats
- CKFloatMultiplyFloatInt - Multiply float and int
- CKFloatOppositeFloat - Negate float
- CKFloatPerSecondFloat - Multiply by delta time (per second)
- CKFloatRandomFloatFloat - Random float between two values
- CKFloatSubtractFloatFloat - Subtract two floats
- CKFloatSubtractFloatInt - Subtract int from float
- CKFloatSubtractIntFloat - Subtract float from int

### Math Functions
- CKFloatArcCosFloat - Arc cosine
- CKFloatArcSinFloat - Arc sine
- CKFloatArcTanFloat - Arc tangent
- CKFloatCosinusFloat - Cosine
- CKFloatDegreToRadianFloat - Convert degrees to radians
- CKFloatRadianToDegreFloat - Convert radians to degrees
- CKFloatSinusFloat - Sine
- CKFloatSqrtFloat - Square root
- CKFloatTanFloat - Tangent

### Type Conversions
- CKFloatSetBool - Convert bool to float
- CKFloatSetInt - Convert int to float

### Vector Operations
- CKFloatDotProduct2dVector - Dot product of 2D vectors
- CKFloatDotProductVector - Dot product of 3D vectors
- CKFloatGetAngle2dVector2dVector - Angle between 2D vectors
- CKFloatGetAngleVector - Angle of vector
- CKFloatGetDistance2dVector - Distance between 2D vectors
- CKFloatGetDistanceVector - Distance between 3D vectors
- CKFloatGetMagnitude2dVector - Magnitude of 2D vector
- CKFloatGetMagnitudeVector - Magnitude of 3D vector

### Entity Queries
- CKFloatGetDistance2dEntity - Distance from 2D entity
- CKFloatGetDistance3dEntity - Distance from 3D entity
- CKFloatGetRadius3dEntity - Radius of 3D entity
- CKFloatGetX3dEntity - X position of 3D entity
- CKFloatGetY3dentity - Y position of 3D entity
- CKFloatGetZ3dEntity - Z position of 3D entity

### Component Access
- CKFloatGetX2dVector - X component of 2D vector
- CKFloatGetY2dVector - Y component of 2D vector
- CKFloatGetXEuler - X component of Euler angles
- CKFloatGetYEuler - Y component of Euler angles
- CKFloatGetZEuler - Z component of Euler angles
- CKFloatGetXQuaternion - X component of quaternion
- CKFloatGetYQuaternion - Y component of quaternion
- CKFloatGetZQuaternion - Z component of quaternion
- CKFloatGetWQuaternion - W component of quaternion

### Object Queries
- CKFloatGetRangeLight - Range of light
- CKFloatGetBackPlaneCamera - Back plane of camera
- CKFloatGetFovCamera - Field of view of camera
- CKFloatGetZoomCamera - Zoom of camera
- CKFloatGetLengthCurve - Length of curve
- CKFloatGetLength2dCurve - Length of 2D curve
- CKFloatGetLengthAnimation - Length of animation
- CKFloatGetLengthCurveCurvePoint - Length of curve to point
- CKFloatGetY2dCurveFloat - Y value at X on 2D curve

### Sound Queries
- CKFloatGetLengthWaveSound - Length of wave sound
- CKFloatGetPanWaveSound - Pan of wave sound
- CKFloatGetPitchWaveSound - Pitch of wave sound
- CKFloatGetVolumeWaveSound - Volume of wave sound
- CKFloatGetDistanceFromListenerWaveSound - Distance from listener

### Mesh Queries
- CKFloatGetVertexWeightMeshInt - Vertex weight

---

## Int Operations (~40 functions)

### Arithmetic Operations
- CKIntAbsoluteInt - Absolute value of int
- CKIntAddIntInt - Add two ints
- CKIntAddIntFloat - Add int and float
- CKIntDivideIntInt - Divide two ints
- CKIntDivideIntFloat - Divide int by float
- CKIntDivideFloatInt - Divide float by int
- CKIntMaxIntInt - Maximum of two ints
- CKIntMaxIntFloat - Maximum of int and float
- CKIntMinIntInt - Minimum of two ints
- CKIntMinIntFloat - Minimum of int and float
- CKIntModuloIntInt - Modulo of two ints
- CKIntMultiplyIntInt - Multiply two ints
- CKIntMultiplyIntFloat - Multiply int and float
- CKIntOppositeInt - Negate int
- CKIntRandomIntInt - Random int between two values
- CKIntSubtractIntInt - Subtract two ints
- CKIntSubtractIntFloat - Subtract float from int
- CKIntSubtractFloatInt - Subtract int from float

### Bitwise Operations
- CKIntAndIntInt - Bitwise AND
- CKIntOrIntInt - Bitwise OR
- CKIntXorIntInt - Bitwise XOR

### Type Conversions
- CKIntSetBool - Convert bool to int
- CKIntSetFloat - Convert float to int

### String Operations
- CKIntGetLengthString - Length of string

### Texture Queries
- CKIntGetWidthTexture - Width of texture
- CKIntGetHeightTexture - Height of texture
- CKIntGetSlotCountTexture - Slot count of texture
- CKIntGetCurrentTexture - Current texture slot

### Sprite Queries
- CKIntGetSlotCountSprite - Slot count of sprite
- CKIntGetCurrentSprite - Current sprite slot

### 2D Entity Queries
- CKIntGetWidth2dEntity - Width of 2D entity
- CKIntGetHeight2dEntity - Height of 2D entity

### Mesh Queries
- CKIntGetVertexCountMesh - Vertex count of mesh
- CKIntGetFaceCountMesh - Face count of mesh
- CKIntGetMaterialCountMesh - Material count of mesh
- CKIntGetChannelCountMesh - Channel count of mesh
- CKIntGetChannelByMaterialMeshMaterial - Channel by material

### Group Queries
- CKIntGetCountGroup - Count of objects in group

### DataArray Queries
- CKIntGetRowCountDataArray - Row count of data array
- CKIntGetColumnCountDataArray - Column count of data array

### ObjectArray Queries
- CKIntGetCountObjectArray - Count of objects in array

### Curve Queries
- CKIntGetCountCurve - Count of curve points

### BeObject Queries
- CKIntGetScriptCountBeObject - Script count of object

### Animation Queries
- CKIntGetAnimationCount3dEntity - Animation count of entity

### Sound Queries
- CKIntGetFrequencyWaveSound - Frequency of wave sound

### Other
- CKIntGetTypeObject - Type ID of object
- CKIntGetRenderedProgressiveMeshVerticesCount - Rendered progressive mesh vertices
- IntGetWidthNoneNone - Screen width
- IntGetHeightNoneNone - Screen height

---

## Bool Operations (~40 functions)

### Logical Operations
- CKBoolAndBoolBool - Boolean AND
- CKBoolOrBoolBool - Boolean OR
- CKBoolXorBoolBool - Boolean XOR
- CKBoolNotBool - Boolean NOT
- CKBoolRandom - Random boolean

### Equality Comparisons
- CKBoolEqualBoolBool - Equality of two bools
- CKBoolNotEqualBoolBool - Inequality of two bools
- CKBoolEqualIntFloat - Equality of int and float
- CKBoolNotEqualIntFloat - Inequality of int and float
- CKBoolEqualMatrixMatrix - Equality of two matrices
- CKBoolNotEqualMatrixMatrix - Inequality of two matrices
- CKBoolEqualDataArrayDataArray - Equality of two data arrays
- CKBoolEqualGroupGroup - Equality of two groups
- CKBoolEqualObjectArrayObjectArray - Equality of two object arrays
- CKBoolEqualStringString - Equality of two strings

### Float Comparisons
- CKBoolInfFloatFloat - Less than (float, float)
- CKBoolSupFloatFloat - Greater than (float, float)
- CKBoolInfEqualFloatFloat - Less than or equal (float, float)
- CKBoolSupEqualFloatFloat - Greater than or equal (float, float)
- CKBoolInfFloatInt - Less than (float, int)
- CKBoolSupFloatInt - Greater than (float, int)
- CKBoolInfEqualFloatInt - Less than or equal (float, int)
- CKBoolSupEqualFloatInt - Greater than or equal (float, int)

### Int Comparisons
- CKBoolInfIntFloat - Less than (int, float)
- CKBoolSupIntFloat - Greater than (int, float)
- CKBoolInfEqualIntFloat - Less than or equal (int, float)
- CKBoolSupEqualIntFloat - Greater than or equal (int, float)
- CKBoolInfIntInt - Less than (int, int)
- CKBoolSupIntInt - Greater than (int, int)
- CKBoolInfEqualIntInt - Less than or equal (int, int)
- CKBoolSupEqualIntInt - Greater than or equal (int, int)

### Object Comparisons
- CKBoolDerivedFromIdId - Check if derived from class
- CKBoolIsInObjectArrayObject - Check if object is in array

### String Operations
- CKBoolContainStringString - Check if string contains substring

### Entity Queries
- CKBoolIsChildOf3dEntity3dEntity - Check if entity is child
- CKBoolIsBodyPartOfBodyPartCharacter - Check if body part belongs to character
- CKBoolIsVisible2dEntity - Check if 2D entity is visible
- CKBoolIsVectorInBboxVector3dEntity - Check if vector is in bounding box

### Collision Tests
- CKBoolCollisionBoxVector - Collision between box and vector
- CKBoolCollisionBoxBox - Collision between two boxes
- CKBoolCollisionBox3dEntity - Collision between box and entity
- CKBoolCollision3dEntity3dEntity - Collision between two entities

### Script Queries
- CKBoolIsActiveScript - Check if script is active
- CKBoolIsActiveBeObject - Check if object is active

### Sound Queries
- CKBoolGetLoopModeWaveSound - Loop mode of wave sound
- CKBoolGetFileStreamingWaveSound - File streaming mode of wave sound
- CKBoolIsPlayingWaveSound - Check if wave sound is playing
- CKBoolIsPausedWaveSound - Check if wave sound is paused

### Type Conversions
- CKBoolSetFloat - Convert float to bool
- CKBoolSetInt - Convert int to bool

---

## Vector Operations (~80 functions)

### Arithmetic Operations
- CKVectorAddVectorVector - Add two vectors
- CKVectorSubtractVectorVector - Subtract two vectors
- CKVectorMultiplyVectorVector - Multiply two vectors (component-wise)
- CKVectorDivideVectorVector - Divide two vectors (component-wise)
- CKVectorMaxVectorVector - Component-wise maximum
- CKVectorMinVectorVector - Component-wise minimum
- CKVectorOppositeVector - Negate vector
- CKVectorInverseVector - Inverse vector
- CKVectorRandom - Random vector
- CKVectorPerSecondVector - Multiply by delta time

### Scalar Operations
- CKVectorMultiplyVectorFloat - Multiply vector by scalar
- CKVectorDivideVectorFloat - Divide vector by scalar
- CKVectorMultiplyVectorMatrix - Multiply vector by matrix

### Advanced Operations
- CKVectorCrossProductVectorVector - Cross product
- CKVectorDotProductVectorVector - Dot product
- CKVectorGetDistanceVector - Distance between vectors
- CKVectorGetAngleVector - Angle between vectors
- CKVectorGetMagnitudeVector - Magnitude of vector
- CKVectorNormalizeVector - Normalize vector
- CKVectorReflectVectorVector - Reflect vector
- CKVectorSymmetryVectorVector - Symmetry of vector
- CKVectorSphericToCartFloatFloat - Spherical to Cartesian

### Entity Operations
- CKVectorGetScale - Scale of 3D entity
- CKVectorGetDir3dEntity - Direction vector of entity
- CKVectorGetUp3dEntity - Up vector of entity
- CKVectorGetRight3dEntity - Right vector of entity
- CKVectorGetPosition3dEntity3dEntity - Position relative to another entity
- CKVectorGetDistance3dEntity3dEntity - Distance between entities
- CKVectorGetCenter3dEntity - Geometric center of entity
- CKVectorTransformVector3dEntity - Transform vector by entity matrix
- CKVectorTransformVectorVector3dEntity - Transform vector by entity matrix
- CKVectorInverseTransformVector3dEntity - Inverse transform vector by entity
- CKVectorInverseTransformVectorVector3dEntity - Inverse transform vector by entity

### Matrix Operations
- CKVectorGetXMatrix - X axis of matrix
- CKVectorGetYMatrix - Y axis of matrix
- CKVectorGetZMatrix - Z axis of matrix
- CKVectorGetPosMatrix - Position of matrix
- CKVectorGetScaleMatrix - Scale of matrix

### Box Operations
- CKVectorGetCenterBox - Center of box
- CKVectorGetMinBox - Minimum of box
- CKVectorGetMaxBox - Maximum of box
- CKVectorGetScaleBox - Scale of box

### Curve Operations
- CKVectorGetCurvePosFloatCurve - Position on curve at parameter
- CKVectorGetCurveTangentFloatCurve - Tangent on curve at parameter

### CurvePoint Operations
- CKVectorGetInTangentCurvePoint - In tangent of curve point
- CKVectorGetOutTangentCurvePoint - Out tangent of curve point

### Mesh Operations
- CKVectorGetVertexNormalMeshInt - Vertex normal
- CKVectorGetVertexPositionMeshInt - Vertex position
- CKVectorGetFaceNormalMeshInt - Face normal
- CKVectorGetFaceVertexIndexPositionMeshInt - Face vertex index position

### Sound Operations
- CKVectorGetConeWaveSound - Cone of wave sound
- CKVectorGetRelPositionWaveSound - Relative position of wave sound
- CKVectorGetRelDirectionWaveSound - Relative direction of wave sound
- CKVectorGetVelocityWaveSound - Velocity of wave sound

### Component Access
- CKVectorSetXVectorFloat - Set X component
- CKVectorSetYVectorFloat - Set Y component
- CKVectorSetZVectorFloat - Set Z component

### Conversion Operations
- CKVectorSetVector2DVector - Convert 2D vector to 3D vector
- CKVectorSetMatrix - Set from matrix
- CKVectorSetPosMatrix - Set position from matrix
- CKVectorSetXMatrix - Set X from matrix
- CKVectorSetYMatrix - Set Y from matrix
- CKVectorSetZMatrix - Set Z from matrix
- CKVectorTransform2dVectorFloat - Transform 2D vector

---

## String Operations (~15 functions)

### Arithmetic
- CKStringAddStringString - Concatenate two strings

### Object Queries
- CKStringGetNameObject - Get object name
- CKStringGetTextSpriteText - Get sprite text

### Sound Queries
- CKStringGetSoundFileNameWaveSound - Get sound file name

### Type Conversions
- CKStringSetGeneric - Convert generic type to string

---

## Matrix Operations (~10 functions)

### Arithmetic Operations
- CKMatrixAddMatrixMatrix - Add two matrices
- CKMatrixSubtractMatrixMatrix - Subtract two matrices
- CKMatrixMultiplyMatrixMatrix - Multiply two matrices
- CKMatrixDivideMatrixMatrix - Divide two matrices
- CKMatrixInverseMatrix - Inverse matrix
- CKMatrixMultiplyMatrixFloat - Multiply matrix by scalar

### Entity Operations
- CKMatrixGetLocalMatrix3dEntity - Get local matrix of entity
- CKMatrixGetWorldMatrix3dEntity - Get world matrix of entity

### Conversion Operations
- CKMatrixSetEuler - Convert Euler angles to matrix
- CKMatrixSetQuaternion - Convert quaternion to matrix
- CKVectorSetMatrix - Set from vector
- CKVectorSetPosMatrix - Set position from matrix
- CKVectorSetXMatrix - Set X from matrix
- CKVectorSetYMatrix - Set Y from matrix
- CKVectorSetZMatrix - Set Z from matrix
- CKMatrixFromRotation - Create rotation matrix

---

## Color Operations (~15 functions)

### Arithmetic Operations
- CKColorAddColorColor - Add two colors
- CKColorSubtractColorColor - Subtract two colors
- CKColorInverseColor - Inverse color
- CKColorRandom - Random color
- CKColorMultiplyFloatColor - Multiply color by scalar

### Component Access
- CKColorSetRedColorFloat - Set red component
- CKColorSetGreenColorFloat - Set green component
- CKColorSetBlueColorFloat - Set blue component
- CKColorSetAlphaColorFloat - Set alpha component

### Material Queries
- CKColorGetSpecularMaterial - Get specular color of material
- CKColorGetSpecularPowerMaterial - Get specular power of material
- CKColorGetDiffuseMaterial - Get diffuse color of material
- CKColorGetEmissiveMaterial - Get emissive color of material
- CKColorGetAmbientMaterial - Get ambient color of material

### Light Queries
- CKColorGetColorLight - Get color of light

### Mesh Queries
- CKColorGetVertexColorMeshInt - Get vertex color
- CKColorGetVertexSpecularColorMeshInt - Get vertex specular color

### Special
- CKColorRainbowFloatFloat - Generate rainbow color

---

## Rect Operations (~15 functions)

### Queries
- CKRectGetViewRect - Get view rectangle
- CKRectGetBox2dEntity - Get bounding box of 2D entity
- CKRectGetBox3dEntity - Get bounding box of 3D entity

### Transform Operations
- CKRectTransformRect2dVector - Transform rectangle by 2D vector
- CKRectTransformRectRect - Transform rectangle by rectangle

### Component Access
- CKRectSetLeftRectFloat - Set left coordinate
- CKRectSetTopRectFloat - Set top coordinate
- CKRectSetRightRectFloat - Set right coordinate
- CKRectSetBottomRectFloat - Set bottom coordinate
- CKRectSetWidthRectFloat - Set width
- CKRectSetHeightRectFloat - Set height
- CKRectSetCenterRect2dVector - Set center position

---

## Box Operations (~5 functions)

### Arithmetic Operations
- CKBoxAddBoxBox - Add two boxes
- CKBoxSubtractBoxBox - Subtract two boxes

### Queries
- CKBoxGetBox3dEntity - Get bounding box of 3D entity
- CKBoxGetHBox3dEntity - Get hierarchical bounding box of 3D entity
- CKBoxGetBoxMesh - Get bounding box of mesh

---

## Quaternion Operations (~5 functions)

### Arithmetic Operations
- CKQuaternionMultiplyQuaternionQuaternion - Multiply two quaternions
- CKQuaternionDivideQuaternionQuaternion - Divide two quaternions

### Conversion Operations
- CKQuaternionSetEuler - Convert Euler angles to quaternion
- CKQuaternionSetMatrix - Convert matrix to quaternion
- CKQuaternionFromRotation - Create quaternion from rotation
- CKColorSetRedColorFloat2 - Set X component
- CKColorSetGreenColorFloat2 - Set Y component
- CKColorSetBlueColorFloat2 - Set Z component
- CKColorSetAlphaColorFloat2 - Set W component

---

## Euler Operations (~5 functions)

### Conversion Operations
- CKEulerSetMatrix - Convert matrix to Euler angles
- CKEulerSetQuaternion - Convert quaternion to Euler angles

### Queries
- CKEulerGetEuler3dEntity3dEntity - Get Euler angles between entities
- CKVectorSetXVectorFloat - Set X component
- CKVectorSetYVectorFloat - Set Y component
- CKVectorSetZVectorFloat - Set Z component

---

## 2D Vector Operations (~30 functions)

### Arithmetic Operations
- CK2dVectorAdd2dVector2dVector - Add two 2D vectors
- CK2dVectorSubtract2dVector2dVector - Subtract two 2D vectors
- CK2dVectorMultiply2dVector2dVector - Multiply two 2D vectors (component-wise)
- CK2dVectorDivide2dVector2dVector - Divide two 2D vectors (component-wise)
- CK2dVectorMax2dVector2dVector - Component-wise maximum
- CK2dVectorMin2dVector2dVector - Component-wise minimum
- CK2dVectorOpposite2dVector - Negate 2D vector
- CK2dVectorInverse2dVector - Inverse 2D vector
- CK2dVectorRandom - Random 2D vector

### Scalar Operations
- CK2dVectorMultiply2dVectorFloat - Multiply 2D vector by scalar
- CK2dVectorDivide2dVectorFloat - Divide 2D vector by scalar

### Advanced Operations
- CKFloatDotProduct2dVector - Dot product
- CKFloatGetDistance2dVector - Distance between 2D vectors
- CKFloatGetAngle2dVector2dVector - Angle between 2D vectors
- CKFloatGetMagnitude2dVector - Magnitude of 2D vector
- CK2dVectorSymmetry2dVector2dVector - Symmetry of 2D vector

### Entity Operations
- CK2dVectorGetPosition2dEntity - Position of 2D entity
- CK2dVectorGetSize2dEntity - Size of 2D entity
- CK2dVectorTransformVector3dEntity - Transform 2D vector by 3D entity

### Camera Operations
- CK2dVectorGetAspectRatioCamera - Aspect ratio of camera

### Curve Operations
- CK2dVectorGetCurvePosFloat2dCurve - Position on 2D curve

### Screen Operations
- CK2dVectorGetScreenOrigin - Get screen origin

### Rect Operations
- CK2dVectorGetPosRect - Position of rectangle
- CK2dVectorGetCenterRect - Center of rectangle
- CK2dVectorGetSizeRect - Size of rectangle
- CK2dVectorGetBRRect - Bottom-right corner of rectangle

### Mesh Operations
- CK2dVectorGetVertexUvsMeshInt - Get UV coordinates of vertex

### Sound Operations
- CK2dVectorGetMinMaxDistanceWaveSound - Min/max distance of wave sound

### Component Access
- CK2dVectorSetX2dVectorFloat - Set X component
- CK2dVectorSetY2dVectorFloat - Set Y component

### Conversion Operations
- CK2dVectorSetFloat - Convert float to 2D vector
- CK2dVectorSetIntInt - Convert two ints to 2D vector
- CK2dVectorSetVector - Convert 3D vector to 2D vector

---

## Object Operations (~50 functions)

### Entity Hierarchy
- CK3dEntityGetParent3dEntity - Get parent of 3D entity
- CK2dEntityGetParent2dEntity - Get parent of 2D entity
- CK3dEntityGetTargetTargetCamera - Get target of target camera
- CK3dEntityGetTargetTargetLight - Get target of target light
- CK3dEntityGetRootCharacter - Get root of character

### Array Operations
- CKObjectArrayAddObjectArrayObject - Add object to array
- CKObjectArrayAddObjectArrayObjectArray - Add objects from array to array
- CKObjectArraySubtractObjectArrayObject - Subtract object from array
- CKObjectArraySubtractObjectArrayObjectArray - Subtract objects from array
- CKObjectArrayMultiplyObjectArrayObjectArray - Intersection of arrays

### Entity Collections
- CKObjectArrayGetChildren3dEntity - Get children of 3D entity
- CKObjectArrayGetMeshList3dEntity - Get mesh list of 3D entity
- CKObjectArrayGetAnimationsCharacter - Get animations of character
- CKObjectArrayGetBodyPartCharacter - Get body parts of character

### Portal Operations
- CKObjectArrayGetPortalsPlace - Get portals of place
- CKObjectArrayGetPortalsPlacePlace - Get portals between places

### Material Collections
- CKObjectArrayGetMaterialListMesh - Get material list of mesh

### Object Lookup
- CKObjectGetObjectByNameString - Get object by name
- CKObjectGetElementObjectArrayInt - Get element from object array
- CKObjectGetElementGroupInt - Get element from group

### Picking Operations
- CKObjectWindowPickIntInt - Pick object at screen coordinates (int)
- CKObjectWindowPick2dVector - Pick object at screen coordinates (2D vector)

### Scene/Level
- CKSceneGetCurrentSceneNoneNone - Get current scene
- CKLevelGetCurrentLevelNoneNone - Get current level

### Material/Texture
- CKMaterialGetMaterialMeshInt - Get material from mesh
- CKMaterialGetMaterial2DEntity - Get material from 2D entity
- CKMaterialGetMaterialSprite3D - Get material from sprite
- CKMaterialGetFaceMaterialMeshInt - Get face material from mesh
- CKTextureGetTextureMaterial - Get texture from material

### Character
- CKCharacterGetCharacter3dEntity - Get character from entity

### Animation
- CKAnimationGetAnimationCharacterString - Get animation by name
- CKObjectAnimationGetAnimation3dEntityString - Get object animation by name
- CKObjectAnimationGetAnimation3dEntityInt - Get object animation by index

### Curve
- CKCurvePointGetPointCurveInt - Get curve point

### Place
- CKPlaceGetPlace3DEntityPlace - Get place from entity
- CKPlaceGetRefPlace3DEntity - Get reference place from entity

### Mesh
- CKMeshGetCurrent3dEntity - Get current mesh from entity

### Script
- CKScriptGetScriptBeObjectInt - Get script by index
- CKScriptGetScriptBeObjectString - Get script by name

### Body Part
- CKBodyPartGetBodyPartByIncludedNameCharacterString - Get body part by name

### Type Casting
- CKBeObjectCastCKBeObject - Cast to BeObject

### Group Operations
- CKIntGetCountGroup - Count of objects in group
- CKObjectGetElementGroupInt - Get element from group

### ObjectArray Operations
- CKIntGetCountObjectArray - Count of objects in array
- CKObjectGetElementObjectArrayInt - Get element from array
- CKBoolIsInObjectArrayObject - Check if object is in array
- CKBoolEqualObjectArrayObjectArray - Equality of arrays

---

## Sound Operations (~15 functions)

### Properties
- CKFloatGetLengthWaveSound - Length of sound
- CKIntGetFrequencyWaveSound - Frequency/sampling rate
- CKFloatGetVolumeWaveSound - Volume/gain
- CKFloatGetPitchWaveSound - Pitch
- CKFloatGetPanWaveSound - Pan

### State
- CKBoolGetLoopModeWaveSound - Loop mode
- CKBoolGetFileStreamingWaveSound - File streaming mode
- CKBoolIsPlayingWaveSound - Is playing
- CKBoolIsPausedWaveSound - Is paused

### Spatial Properties
- CKVectorGetRelPositionWaveSound - Relative position
- CKVectorGetRelDirectionWaveSound - Relative direction
- CKFloatGetDistanceFromListenerWaveSound - Distance from listener
- CKVectorGetConeWaveSound - Cone parameters
- CK2dVectorGetMinMaxDistanceWaveSound - Min/max distance
- CKVectorGetVelocityWaveSound - Velocity

### File
- CKStringGetSoundFileNameWaveSound - Sound file name

---

## Time Operations (1 function)

- CKTimeGetPlayedMS - Get played time in milliseconds

---

## Animation Operations (~5 functions)

- CKFloatGetLengthAnimation - Length of animation
- CKIntGetAnimationCount3dEntity - Animation count of entity
- CKAnimationGetAnimationCharacterString - Get animation by name
- CKObjectAnimationGetAnimation3dEntityString - Get object animation by name
- CKObjectAnimationGetAnimation3dEntityInt - Get object animation by index

---

## Mesh Operations (~15 functions)

### Properties
- CKIntGetVertexCountMesh - Vertex count
- CKIntGetFaceCountMesh - Face count
- CKIntGetMaterialCountMesh - Material count
- CKIntGetChannelCountMesh - Channel count
- CKIntGetChannelByMaterialMeshMaterial - Channel by material
- CKIntGetRenderedProgressiveMeshVerticesCount - Rendered progressive mesh vertices

### Vertex Data
- CKVectorGetVertexNormalMeshInt - Vertex normal
- CKVectorGetVertexPositionMeshInt - Vertex position
- CKFloatGetVertexWeightMeshInt - Vertex weight
- CKColorGetVertexColorMeshInt - Vertex color
- CKColorGetVertexSpecularColorMeshInt - Vertex specular color

### Face Data
- CKVectorGetFaceNormalMeshInt - Face normal
- CKVectorGetFaceVertexIndexPositionMeshInt - Face vertex index position

### UV Data
- CK2dVectorGetVertexUvsMeshInt - UV coordinates

### Material
- CKMaterialGetMaterialMeshInt - Get material
- CKMaterialGetFaceMaterialMeshInt - Get face material

### Bounding Box
- CKBoxGetBoxMesh - Get bounding box

---

## Material Operations (~5 functions)

- CKMaterialGetMaterialMeshInt - Get material from mesh
- CKMaterialGetMaterial2DEntity - Get material from 2D entity
- CKMaterialGetMaterialSprite3D - Get material from sprite
- CKMaterialGetFaceMaterialMeshInt - Get face material from mesh
- CKTextureGetTextureMaterial - Get texture from material

---

## Texture Operations (~4 functions)

- CKIntGetWidthTexture - Width
- CKIntGetHeightTexture - Height
- CKIntGetSlotCountTexture - Slot count
- CKIntGetCurrentTexture - Current slot

---

## Sprite Operations (~2 functions)

- CKIntGetSlotCountSprite - Slot count
- CKIntGetCurrentSprite - Current slot
- CKStringGetTextSpriteText - Get text

---

## Camera Operations (~4 functions)

- CKFloatGetFovCamera - Field of view
- CKFloatGetBackPlaneCamera - Back plane (far clip)
- CKFloatGetZoomCamera - Zoom
- CK2dVectorGetAspectRatioCamera - Aspect ratio
- CKFloatGetLengthCurve - Near clip

---

## Curve Operations (~6 functions)

- CKFloatGetLengthCurve - Length of curve
- CKFloatGetLength2dCurve - Length of 2D curve
- CKIntGetCountCurve - Point count
- CKVectorGetCurvePosFloatCurve - Position at parameter
- CKVectorGetCurveTangentFloatCurve - Tangent at parameter
- CKFloatGetY2dCurveFloat - Y value at X
- CKFloatGetLengthCurveCurvePoint - Length to point
- CKCurvePointGetPointCurveInt - Get curve point
- CKVectorGetInTangentCurvePoint - In tangent
- CKVectorGetOutTangentCurvePoint - Out tangent

---

## Place/Portal Operations (~4 functions)

- CKPlaceGetPlace3DEntityPlace - Get place
- CKPlaceGetRefPlace3DEntity - Get reference place
- CKObjectArrayGetPortalsPlace - Get portals
- CKObjectArrayGetPortalsPlacePlace - Get portals between places

---

## Collision Operations (~6 functions)

- CKBoolCollisionBoxVector - Box vs vector collision
- CKBoolCollisionBoxBox - Box vs box collision
- CKBoolCollisionBox3dEntity - Box vs entity collision
- CKBoolCollision3dEntity3dEntity - Entity vs entity collision
- CKBoolIsChildOf3dEntity3dEntity - Check if child
- CKBoolIsBodyPartOfBodyPartCharacter - Check if body part
- CKBoolIsVectorInBboxVector3dEntity - Check if vector in bounding box

---

## DataArray Operations (~3 functions)

- CKIntGetRowCountDataArray - Row count
- CKIntGetColumnCountDataArray - Column count
- CKBoolEqualDataArrayDataArray - Equality check

---

## Group Operations (~2 functions)

- CKIntGetCountGroup - Object count
- CKObjectGetElementGroupInt - Get element
- CKIdGetGroupTypeGroup - Get group type
- CKBoolEqualGroupGroup - Equality check

---

## Script Operations (~3 functions)

- CKIntGetScriptCountBeObject - Script count
- CKScriptGetScriptBeObjectInt - Get script by index
- CKScriptGetScriptBeObjectString - Get script by name
- CKBoolIsActiveScript - Is active
- CKBoolIsActiveBeObject - Is object active

---

## General Conversion Operations (~10 functions)

### Generic Equality
- CKGenericEqual1Dword - Equality for 1 dword types
- CKGenericNotEqual1Dword - Inequality for 1 dword types
- CKGenericEqual2Dword - Equality for 2 dword types
- CKGenericNotEqual2Dword - Inequality for 2 dword types
- CKGenericEqual3Dword - Equality for 3 dword types
- CKGenericNotEqual3Dword - Inequality for 3 dword types
- CKGenericEqual4Dword - Equality for 4 dword types
- CKGenericNotEqual4Dword - Inequality for 4 dword types

### String Conversions
- CKGenericSetString - Convert to string
- CKStringSetGeneric - Convert from string
- CKFloatSetInt - Convert int to float
- CKIntSetFloat - Convert float to int
- CKBoolSetFloat - Convert float to bool
- CKBoolSetInt - Convert int to bool
- CKIntSetBool - Convert bool to int
- CKFloatSetBool - Convert bool to float

---

## Summary

Total functions: 422

### By Category:
- Float Operations: ~60 functions
- Int Operations: ~40 functions
- Bool Operations: ~40 functions
- Vector Operations: ~80 functions
- String Operations: ~15 functions
- Matrix Operations: ~10 functions
- Color Operations: ~15 functions
- Rect Operations: ~15 functions
- Box Operations: ~5 functions
- Quaternion Operations: ~5 functions
- Euler Operations: ~5 functions
- 2D Vector Operations: ~30 functions
- Object Operations: ~50 functions
- Sound Operations: ~15 functions
- Time Operations: 1 function
- Animation Operations: ~5 functions
- Mesh Operations: ~15 functions
- Material Operations: ~5 functions
- Texture Operations: ~4 functions
- Sprite Operations: ~2 functions
- Camera Operations: ~4 functions
- Curve Operations: ~6 functions
- Place/Portal Operations: ~4 functions
- Collision Operations: ~6 functions
- DataArray Operations: ~3 functions
- Group Operations: ~2 functions
- Script Operations: ~3 functions
- General Conversion Operations: ~10 functions

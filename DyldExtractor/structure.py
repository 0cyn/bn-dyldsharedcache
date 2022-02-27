import ctypes
from typing import Type, TypeVar

_T = TypeVar("_T", bound="Structure")


class Structure(ctypes.LittleEndianStructure):
	"""
		A base class for all structures.
	"""

	_fileOff_: int

	def __new__(cls: Type[_T], dataSource: bytes = None, offset: int = 0) -> _T:
		if dataSource:
			instance = None
			if memoryview(dataSource).readonly:
				instance = cls.from_buffer_copy(dataSource, offset)
			else:
				instance = cls.from_buffer(dataSource, offset)

			instance._fileOff_ = offset
			return instance
		else:
			return super().__new__(cls)

	def __init__(self, dataSource: bytes = None, offset: int = 0) -> None:
		...

	def __len__(self) -> int:
		return ctypes.sizeof(self)

	def __str__(self) -> str:
		string = super().__str__()
		for field in self._fields_:
			fieldName = field[0]
			fieldData = getattr(self, field[0])

			if isinstance(fieldData, ctypes.Array):
				fieldData = list(fieldData)
			elif isinstance(fieldData, int):
				fieldData = hex(fieldData)

			string += f"\n\t{field[0]}: {fieldData}"

		return string
